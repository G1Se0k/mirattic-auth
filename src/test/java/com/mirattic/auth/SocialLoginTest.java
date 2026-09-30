package com.mirattic.auth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.authentication;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.jayway.jsonpath.JsonPath;
import com.mirattic.auth.account.SocialLogin;
import jakarta.servlet.http.Cookie;
import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import org.hamcrest.Matchers;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.FactorGrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.web.util.UriComponentsBuilder;

/** Kakao / Naver sign-in (docs/oauth-oidc.md "Social login"), with the providers stubbed by SocialStub. */
class SocialLoginTest extends IntegrationTest {

	@Autowired SocialLogin socialLogin;
	@Autowired ClientRegistrationRepository registrations;

	private static String kakao(String id, String email, String nickname) {
		return """
				{"id":%s,"kakao_account":{%s"profile":{"nickname":"%s"}}}""".formatted(id,
				email == null ? "" : "\"email\":\"" + email + "\",", nickname);
	}

	private static String naver(String id, String email, String nickname) {
		return """
				{"resultcode":"00","message":"success","response":{"id":"%s","email":"%s","nickname":"%s"}}"""
				.formatted(id, email, nickname);
	}

	private static String providerId() {
		return String.valueOf(Math.abs(UUID.randomUUID().getMostSignificantBits()));
	}

	@Test
	void firstKakaoSignInCreatesAnAccountAndTheNextOneFindsIt() throws Exception {
		String kakaoId = providerId();
		Cookie session = signIn("kakao", kakao(kakaoId, "k@example.com", "카카오친구"), null).session();
		String uid = jdbc.queryForObject("SELECT user_id FROM user_identities WHERE provider = 'KAKAO' AND subject = ?",
				String.class, kakaoId);
		assertThat(jdbc.queryForObject("SELECT display_name FROM users WHERE id = ?", String.class, uid)).isEqualTo("카카오친구");

		// Account page: the Kakao email, login method, no password section.
		mvc.perform(get("/account").cookie(session)).andExpect(status().isOk())
				.andExpect(content().string(Matchers.containsString("k@example.com")))
				.andExpect(content().string(Matchers.containsString("카카오")))
				.andExpect(content().string(Matchers.not(Matchers.containsString("비밀번호 변경"))));

		signIn("kakao", kakao(kakaoId, "k@example.com", "바뀐이름"), null);
		assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM user_identities WHERE provider = 'KAKAO' AND subject = ?",
				Integer.class, kakaoId)).isOne();
		assertThat(jdbc.queryForObject("SELECT display_name FROM users WHERE id = ?", String.class, uid)).isEqualTo("카카오친구");
	}

	@Test
	void sameEmailAsAPasswordAccountIsStillASeparateAccount() throws Exception {
		String email = email();
		String local = signup(email, "password-1", "L");
		String naverId = "nv-" + UUID.randomUUID();
		signIn("naver", naver(naverId, email, "네이버친구"), null);
		String social = jdbc.queryForObject("SELECT user_id FROM user_identities WHERE provider = 'NAVER' AND subject = ?",
				String.class, naverId);
		assertThat(social).isNotEqualTo(local); // never merged by email
	}

	@Test
	void socialSignInContinuesTheClientsAuthorizationWithSubAndAuthTime() throws Exception {
		String authorize = "/oauth2/authorize?response_type=code&client_id=" + CLIENT + "&redirect_uri=" + REDIRECT
				+ "&scope=openid%20profile%20email&state=st1&code_challenge=" + s256(VERIFIER) + "&code_challenge_method=S256";
		MockHttpServletResponse saved = mvc.perform(get(URI.create(authorize)).accept(MediaType.TEXT_HTML))
				.andExpect(status().is3xxRedirection()).andReturn().getResponse();
		assertThat(saved.getRedirectedUrl()).endsWith("/login");

		String kakaoId = providerId();
		SignIn in = signIn("kakao", kakao(kakaoId, null, "앱에서온사람"), saved.getCookie("SESSION"));
		assertThat(in.redirect()).contains("/oauth2/authorize");
		String location = mvc.perform(get(URI.create(in.redirect())).cookie(in.session()))
				.andExpect(status().is3xxRedirection()).andReturn().getResponse().getRedirectedUrl();
		assertThat(location).startsWith(REDIRECT + "?code=");
		String code = URLDecoder.decode(UriComponentsBuilder.fromUriString(location).build().getQueryParams()
				.getFirst("code"), StandardCharsets.UTF_8);

		String tokens = exchange(code);
		String claims = claims(JsonPath.read(tokens, "$.id_token"));
		String uid = jdbc.queryForObject("SELECT user_id FROM user_identities WHERE provider = 'KAKAO' AND subject = ?",
				String.class, kakaoId);
		assertThat((String) JsonPath.read(claims, "$.sub")).isEqualTo(uid);
		assertThat((String) JsonPath.read(claims, "$.name")).isEqualTo("앱에서온사람");
		assertThat(((Number) JsonPath.read(claims, "$.auth_time")).longValue())
				.isCloseTo(System.currentTimeMillis() / 1000, org.assertj.core.data.Offset.offset(30L));
		assertThat(claims).doesNotContain("\"email\""); // Kakao gave none
	}

	@Test
	void reauthenticationIsForwardedToTheProvider() throws Exception {
		// A client asked for prompt=login (e.g. Sync account deletion); the user picks Kakao or Naver.
		String authorize = "/oauth2/authorize?response_type=code&client_id=" + CLIENT + "&redirect_uri=" + REDIRECT
				+ "&scope=openid&state=st1&prompt=login&code_challenge=" + s256(VERIFIER) + "&code_challenge_method=S256";
		Cookie session = mvc.perform(get(URI.create(authorize)).accept(MediaType.TEXT_HTML)).andReturn().getResponse()
				.getCookie("SESSION");
		assertThat(mvc.perform(get("/oauth2/authorization/kakao").cookie(session)).andReturn().getResponse()
				.getRedirectedUrl()).contains("prompt=login");
		assertThat(mvc.perform(get("/oauth2/authorization/naver").cookie(session)).andReturn().getResponse()
				.getRedirectedUrl()).contains("auth_type=reauthenticate");

		// An ordinary sign-in does not force the provider's login screen.
		assertThat(mvc.perform(get("/oauth2/authorization/kakao")).andReturn().getResponse().getRedirectedUrl())
				.doesNotContain("prompt=").doesNotContain("auth_type=");
	}

	@Test
	void disabledAccountCannotSignIn() throws Exception {
		String kakaoId = providerId();
		signIn("kakao", kakao(kakaoId, null, "x"), null);
		jdbc.update("UPDATE users SET status = 'DISABLED' WHERE id = (SELECT user_id FROM user_identities "
				+ "WHERE provider = 'KAKAO' AND subject = ?)", kakaoId);
		assertThat(start("kakao", kakao(kakaoId, null, "x"), null).getRedirectedUrl()).endsWith("/login?social_error");
	}

	@Test
	void concurrentFirstSignInsOfOneProviderAccountMakeOneAccount() throws Exception {
		String kakaoId = providerId();
		String code = SocialStub.code(kakao(kakaoId, null, "동시"));
		OAuth2UserRequest request = new OAuth2UserRequest(registrations.findByRegistrationId("kakao"),
				new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, "at-" + code, Instant.now(),
						Instant.now().plusSeconds(60)));
		ExecutorService pool = Executors.newFixedThreadPool(6);
		try {
			List<Future<String>> results = new ArrayList<>();
			for (int i = 0; i < 6; i++) {
				results.add(pool.submit(() -> socialLogin.loadUser(request).getName()));
			}
			Set<String> uids = new HashSet<>();
			for (Future<String> f : results) {
				uids.add(f.get()); // none fails (duplicate key / deadlock are retried)
			}
			assertThat(uids).hasSize(1);
		} finally {
			pool.shutdown();
		}
		assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM user_identities WHERE provider = 'KAKAO' AND subject = ?",
				Integer.class, kakaoId)).isOne();
	}

	@Test
	void privacyPolicyIsPublicAndLinkedFromEveryPage() throws Exception {
		mvc.perform(get("/privacy")).andExpect(status().isOk())
				.andExpect(content().string(Matchers.containsString("개인정보처리방침")))
				.andExpect(content().string(Matchers.containsString("Resend")))
				.andExpect(content().string(Matchers.containsString("카카오")));
		mvc.perform(get("/login")).andExpect(content().string(Matchers.containsString("href=\"/privacy\"")));
	}

	@Test
	void loginPageOffersEveryProvider() throws Exception {
		mvc.perform(get("/login")).andExpect(status().isOk())
				.andExpect(content().string(Matchers.containsString("/oauth2/authorization/kakao")))
				.andExpect(content().string(Matchers.containsString("/oauth2/authorization/naver")))
				.andExpect(content().string(Matchers.containsString("/oauth2/authorization/google")));
		// Tab from the email lands on the password, not on the reset link.
		String page = mvc.perform(get("/login")).andReturn().getResponse().getContentAsString(StandardCharsets.UTF_8);
		assertThat(page.indexOf("id=\"username\"")).isLessThan(page.indexOf("id=\"password\""));
		assertThat(page.indexOf("id=\"password\"")).isLessThan(page.indexOf("/password/reset"));
	}

	@Test
	void googleSignInIsKeyedBySubAndKeepsOnlyAVerifiedEmail() throws Exception {
		String sub = providerId();
		Cookie session = googleSignIn(null, sub, "unverified@example.com", false, "구글친구", "dev-google").session();
		String uid = owner("GOOGLE", sub);
		assertThat(uid).isNotNull();
		assertThat(jdbc.queryForObject("SELECT display_name FROM users WHERE id = ?", String.class, uid)).isEqualTo("구글친구");
		assertThat(jdbc.queryForObject("SELECT email FROM user_identities WHERE provider = 'GOOGLE' AND subject = ?",
				String.class, sub)).isNull();
		mvc.perform(get("/account").cookie(session)).andExpect(status().isOk())
				.andExpect(content().string(Matchers.containsString("<strong>Google</strong>")))
				.andExpect(content().string(Matchers.not(Matchers.containsString("/account/unlink/google")))); // the only one

		// The same Google account with a new (verified) address: same Mirattic account, the address is kept.
		googleSignIn(null, sub, "g@example.com", true, "구글친구", "dev-google");
		assertThat(owner("GOOGLE", sub)).isEqualTo(uid);
		assertThat(jdbc.queryForObject("SELECT email FROM user_identities WHERE provider = 'GOOGLE' AND subject = ?",
				String.class, sub)).isEqualTo("g@example.com");

		// An ID token issued to another app is refused.
		String other = providerId();
		assertThat(googleCallback(null, other, "x@example.com", true, "남", "someone-else").getRedirectedUrl())
				.endsWith("/login?social_error");
		assertThat(owner("GOOGLE", other)).isNull();
	}

	@Test
	void googleReauthenticationAndLinkingAskToPickTheAccount() throws Exception {
		String authorize = "/oauth2/authorize?response_type=code&client_id=" + CLIENT + "&redirect_uri=" + REDIRECT
				+ "&scope=openid&state=st1&prompt=login&code_challenge=" + s256(VERIFIER) + "&code_challenge_method=S256";
		Cookie pending = mvc.perform(get(URI.create(authorize)).accept(MediaType.TEXT_HTML)).andReturn().getResponse()
				.getCookie("SESSION");
		assertThat(mvc.perform(get("/oauth2/authorization/google").cookie(pending)).andReturn().getResponse()
				.getRedirectedUrl()).contains("prompt=select_account");
		assertThat(mvc.perform(get("/oauth2/authorization/google")).andReturn().getResponse().getRedirectedUrl())
				.doesNotContain("prompt=");

		String email = email();
		String uid = signup(email, "password-1", "L");
		Cookie session = login(email, "password-1");
		mvc.perform(post("/account/link/google").with(csrf()).cookie(session))
				.andExpect(redirectedUrl("/oauth2/authorization/google"));
		String sub = providerId();
		assertThat(googleSignIn(session, sub, email, true, "L", "dev-google").redirect()).endsWith("/");
		assertThat(owner("GOOGLE", sub)).isEqualTo(uid);
		assertThat(jdbc.queryForList("SELECT CONCAT(type, ':', detail) FROM security_events WHERE user_id = ? "
				+ "AND type = 'LINKED'", String.class, uid)).containsExactly("LINKED:Google");
	}

	@Test
	void aPasswordAccountAddsKakaoAndSignsInWithEither() throws Exception {
		String email = email();
		String uid = signup(email, "password-1", "L");
		Cookie session = login(email, "password-1");
		mvc.perform(post("/account/link/kakao").with(csrf()).cookie(session))
				.andExpect(redirectedUrl("/oauth2/authorization/kakao"));
		// The user picks which Kakao account: Kakao asks for its login.
		assertThat(mvc.perform(get("/oauth2/authorization/kakao").cookie(session)).andReturn().getResponse()
				.getRedirectedUrl()).contains("prompt=login");

		String kakaoId = providerId();
		SignIn in = signIn("kakao", kakao(kakaoId, "other@example.com", "카카오이름"), session);
		assertThat(in.redirect()).endsWith("/");
		assertThat(owner("KAKAO", kakaoId)).isEqualTo(uid);
		mvc.perform(get("/account").cookie(in.session())).andExpect(status().isOk())
				.andExpect(content().string(Matchers.containsString("/account/unlink/kakao")))
				.andExpect(content().string(Matchers.containsString("/account/link/naver")));
		// Kakao alone now signs in to the same account; the name and contact email stay.
		signIn("kakao", kakao(kakaoId, "other@example.com", "카카오이름"), null);
		assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM users u WHERE u.id = ? AND u.display_name = 'L'",
				Integer.class, uid)).isOne();

		// Removing it: allowed while the password remains. Whoever signed in with it (elsewhere) is out.
		Cookie laptop = login(email, "password-1");
		Cookie viaKakao = signIn("kakao", kakao(kakaoId, "other@example.com", "카카오이름"), null).session();
		mvc.perform(get("/account").cookie(viaKakao)).andExpect(status().isOk());
		mvc.perform(post("/account/unlink/kakao").with(csrf()).cookie(laptop))
				.andExpect(redirectedUrl("/account?unlinked#methods"));
		assertThat(owner("KAKAO", kakaoId)).isNull();
		mvc.perform(get("/account").cookie(viaKakao)).andExpect(redirectedUrl("/login"));
		mvc.perform(get("/account").cookie(laptop)).andExpect(status().isOk());

		// Removed from a browser that signed in with it: that browser is out too.
		String naverId = "nv-" + UUID.randomUUID();
		MockHttpServletResponse linked = link(laptop, "naver", naver(naverId, email, "네이버이름"));
		Cookie viaNaver = linked.getCookie("SESSION"); // the link was a Naver sign-in of this browser
		mvc.perform(post("/account/unlink/naver").with(csrf()).cookie(viaNaver))
				.andExpect(redirectedUrl("/login?unlinked"));
		mvc.perform(get("/account").cookie(viaNaver)).andExpect(redirectedUrl("/login"));
		assertThat(owner("NAVER", naverId)).isNull();
		assertThat(jdbc.queryForList("SELECT CONCAT(type, ':', detail) FROM security_events WHERE user_id = ? "
				+ "AND type IN ('LINKED', 'UNLINKED') ORDER BY id", String.class, uid))
				.containsExactly("LINKED:카카오", "UNLINKED:카카오", "LINKED:네이버", "UNLINKED:네이버");
	}

	@Test
	void aLinkNeverTakesAnotherAccountsIdentityOrAddsASecondOfOneProvider() throws Exception {
		String kakaoTaken = providerId();
		signIn("kakao", kakao(kakaoTaken, null, "남"), null);
		String theirs = owner("KAKAO", kakaoTaken);

		String email = email();
		String uid = signup(email, "password-1", "L");
		Cookie session = login(email, "password-1");
		assertThat(link(session, "kakao", kakao(kakaoTaken, null, "남")).getRedirectedUrl())
				.endsWith("/account?link_error=taken");
		assertThat(owner("KAKAO", kakaoTaken)).isEqualTo(theirs);
		mvc.perform(get("/account").cookie(session)).andExpect(status().isOk()) // still signed in as before
				.andExpect(content().string(Matchers.containsString("L 님")));

		String mine = providerId();
		MockHttpServletResponse linked = link(session, "kakao", kakao(mine, null, "나"));
		assertThat(linked.getRedirectedUrl()).endsWith("/");
		session = linked.getCookie("SESSION"); // a sign-in: new session id
		assertThat(link(session, "kakao", kakao(providerId(), null, "나2")).getRedirectedUrl())
				.endsWith("/account?link_error=exists");
		assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM user_identities WHERE user_id = ?", Integer.class, uid))
				.isEqualTo(2);
	}

	@Test
	void aLinkFinishingAfterTheAccountWasDeletedAddsNothing() throws Exception {
		String email = email();
		String uid = signup(email, "password-1", "L");
		Cookie session = login(email, "password-1");
		mvc.perform(post("/account/link/kakao").with(csrf()).cookie(session));
		// The account is deleted (another tab) while this browser is at Kakao.
		jdbc.update("UPDATE users SET status = 'DELETED' WHERE id = ?", uid);
		String kakaoId = providerId();
		assertThat(start("kakao", kakao(kakaoId, null, "늦은연결"), session).getRedirectedUrl())
				.endsWith("/account?link_error=failed");
		assertThat(owner("KAKAO", kakaoId)).isNull();
		assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM security_events WHERE user_id = ? AND type = 'LINKED'",
				Integer.class, uid)).isZero();
	}

	@Test
	void theLastSignInMethodStays() throws Exception {
		String kakaoId = providerId();
		Cookie session = signIn("kakao", kakao(kakaoId, null, "혼자")).session();
		mvc.perform(post("/account/unlink/kakao").with(csrf()).cookie(session)).andExpect(status().isOk())
				.andExpect(content().string(Matchers.containsString("마지막 로그인 방법")));
		assertThat(owner("KAKAO", kakaoId)).isNotNull();
		mvc.perform(get("/account").cookie(session))
				.andExpect(content().string(Matchers.not(Matchers.containsString("/account/unlink/kakao"))));
	}

	@Test
	void changingSignInMethodsNeedsARecentSignIn() throws Exception {
		String email = email();
		String uid = signup(email, "password-1", "L");
		var old = new UsernamePasswordAuthenticationToken(uid, null, List.of(new SimpleGrantedAuthority("ROLE_USER"),
				FactorGrantedAuthority.withAuthority(FactorGrantedAuthority.PASSWORD_AUTHORITY)
						.issuedAt(Instant.now().minusSeconds(11 * 60)).build()));
		mvc.perform(post("/account/link/kakao").with(csrf()).with(authentication(old)))
				.andExpect(redirectedUrl("/login?reauth"));
		mvc.perform(post("/account/unlink/kakao").with(csrf()).with(authentication(old)))
				.andExpect(redirectedUrl("/login?reauth"));
	}

	@Test
	void anAbandonedLinkIsNotAppliedToALaterSignIn() throws Exception {
		String email = email();
		String uid = signup(email, "password-1", "L");
		Cookie session = login(email, "password-1");
		mvc.perform(post("/account/link/naver").with(csrf()).cookie(session));
		// Cancelled at Naver: back to the account page, still signed in, nothing pending.
		Cookie s = mvc.perform(get("/oauth2/authorization/naver").cookie(session)).andReturn().getResponse()
				.getCookie("SESSION");
		String cancelled = mvc.perform(get("/login/oauth2/code/naver").param("error", "access_denied")
				.param("state", "x").cookie(s != null ? s : session)).andReturn().getResponse().getRedirectedUrl();
		assertThat(cancelled).endsWith("/account?link_error=failed");

		mvc.perform(post("/account/link/naver").with(csrf()).cookie(session));
		mvc.perform(get("/login").cookie(session)).andExpect(status().isOk()); // went to sign in instead
		String naverId = "nv-" + UUID.randomUUID();
		signIn("naver", naver(naverId, email, "다른사람"), session);
		assertThat(owner("NAVER", naverId)).isNotEqualTo(uid);
	}

	private String owner(String provider, String subject) {
		return jdbc.query("SELECT user_id FROM user_identities WHERE provider = ? AND subject = ?",
				rs -> rs.next() ? rs.getString(1) : null, provider, subject);
	}

	private MockHttpServletResponse link(Cookie session, String provider, String userInfo) throws Exception {
		mvc.perform(post("/account/link/" + provider).with(csrf()).cookie(session))
				.andExpect(redirectedUrl("/oauth2/authorization/" + provider));
		return start(provider, userInfo, session);
	}

	private SignIn signIn(String provider, String userInfo) throws Exception {
		return signIn(provider, userInfo, null);
	}

	record SignIn(Cookie session, String redirect) {
	}

	private SignIn signIn(String provider, String userInfo, Cookie session) throws Exception {
		MockHttpServletResponse cb = start(provider, userInfo, session);
		assertThat(cb.getRedirectedUrl()).doesNotContain("error");
		Cookie next = cb.getCookie("SESSION");
		return new SignIn(next != null ? next : session, cb.getRedirectedUrl());
	}

	private SignIn googleSignIn(Cookie session, String sub, String email, boolean verified, String name, String audience)
			throws Exception {
		MockHttpServletResponse cb = googleCallback(session, sub, email, verified, name, audience);
		assertThat(cb.getRedirectedUrl()).doesNotContain("error");
		Cookie next = cb.getCookie("SESSION");
		return new SignIn(next != null ? next : session, cb.getRedirectedUrl());
	}

	/** As {@link #start}, for Google: its ID token must answer the nonce of the authorization request. */
	private MockHttpServletResponse googleCallback(Cookie session, String sub, String email, boolean verified,
			String name, String audience) throws Exception {
		var req = get("/oauth2/authorization/google");
		if (session != null) {
			req.cookie(session);
		}
		MockHttpServletResponse go = mvc.perform(req).andExpect(status().is3xxRedirection()).andReturn().getResponse();
		assertThat(go.getRedirectedUrl()).startsWith("https://google.test/authorize").contains("scope=openid");
		Cookie s = go.getCookie("SESSION") != null ? go.getCookie("SESSION") : session;
		var params = UriComponentsBuilder.fromUriString(go.getRedirectedUrl()).build().getQueryParams();
		String state = URLDecoder.decode(params.getFirst("state"), StandardCharsets.UTF_8);
		String nonce = URLDecoder.decode(params.getFirst("nonce"), StandardCharsets.UTF_8);
		return mvc.perform(get("/login/oauth2/code/google").param("state", state).cookie(s)
				.param("code", SocialStub.google(audience, nonce, sub, email, verified, name))).andReturn().getResponse();
	}

	/** /oauth2/authorization/{provider} → (provider signs the user in) → /login/oauth2/code/{provider}. */
	private MockHttpServletResponse start(String provider, String userInfo, Cookie session) throws Exception {
		var req = get("/oauth2/authorization/" + provider);
		if (session != null) {
			req.cookie(session);
		}
		MockHttpServletResponse go = mvc.perform(req).andExpect(status().is3xxRedirection()).andReturn().getResponse();
		assertThat(go.getRedirectedUrl()).startsWith("https://" + provider + ".test/authorize");
		Cookie s = go.getCookie("SESSION") != null ? go.getCookie("SESSION") : session;
		String state = URLDecoder.decode(UriComponentsBuilder.fromUriString(go.getRedirectedUrl()).build()
				.getQueryParams().getFirst("state"), StandardCharsets.UTF_8);
		return mvc.perform(get("/login/oauth2/code/" + provider).param("code", SocialStub.code(userInfo))
				.param("state", state).cookie(s)).andReturn().getResponse();
	}

}
