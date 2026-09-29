package com.mirattic.auth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
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
	void loginPageOffersBothProviders() throws Exception {
		mvc.perform(get("/login")).andExpect(status().isOk())
				.andExpect(content().string(Matchers.containsString("/oauth2/authorization/kakao")))
				.andExpect(content().string(Matchers.containsString("/oauth2/authorization/naver")));
	}

	record SignIn(Cookie session, String redirect) {
	}

	private SignIn signIn(String provider, String userInfo, Cookie session) throws Exception {
		MockHttpServletResponse cb = start(provider, userInfo, session);
		assertThat(cb.getRedirectedUrl()).doesNotContain("error");
		Cookie next = cb.getCookie("SESSION");
		return new SignIn(next != null ? next : session, cb.getRedirectedUrl());
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
