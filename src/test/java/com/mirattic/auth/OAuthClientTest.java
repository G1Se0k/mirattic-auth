package com.mirattic.auth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.jayway.jsonpath.JsonPath;
import java.net.URI;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import jakarta.servlet.http.Cookie;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.web.util.UriComponentsBuilder;

/** Confidential clients (client_secret_basic + PKCE), refresh rotation, revocation. docs/clients.md */
class OAuthClientTest extends IntegrationTest {

	@Autowired OAuth2AuthorizationService authorizations;
	@Autowired RegisteredClientRepository clients;

	record Session(String uid, String email, Cookie browser) {
	}

	Session newUser() throws Exception {
		String email = email();
		String uid = signup(email, "password-1", "C");
		return new Session(uid, email, login(email, "password-1"));
	}

	@Test
	void tokenEndpointRequiresTheClientSecretAndPkceVerifier() throws Exception {
		Session s = newUser();
		String code = authorize(s.browser());
		token("wrong-secret", "grant_type", "authorization_code", "code", code, "redirect_uri", REDIRECT,
				"code_verifier", VERIFIER).andExpect(status().isUnauthorized());
		token(SECRET, "grant_type", "authorization_code", "code", code, "redirect_uri", REDIRECT)
				.andExpect(status().isBadRequest());
		token(SECRET, "grant_type", "authorization_code", "code", code, "redirect_uri", REDIRECT,
				"code_verifier", "x".repeat(43)).andExpect(status().isBadRequest());
	}

	@Test
	void promptLoginAlwaysAsksAgainThenTheReplayGetsACodeWithAFreshAuthTime() throws Exception {
		Session s = newUser();
		URI authorize = URI.create("/oauth2/authorize?response_type=code&client_id=" + CLIENT + "&redirect_uri=" + REDIRECT
				+ "&scope=openid&state=st1&prompt=login&code_challenge=" + s256(VERIFIER) + "&code_challenge_method=S256");
		// Signed in a moment ago, still asked again.
		MockHttpServletResponse asked = mvc.perform(get(authorize).cookie(s.browser()).accept(MediaType.TEXT_HTML))
				.andReturn().getResponse();
		assertThat(asked.getRedirectedUrl()).endsWith("/login");
		Cookie pending = asked.getCookie("SESSION");

		MockHttpServletResponse signedIn = mvc.perform(post("/login").param("username", s.email())
				.param("password", "password-1").with(csrf()).cookie(pending)).andReturn().getResponse();
		assertThat(signedIn.getRedirectedUrl()).contains("/oauth2/authorize").contains("prompt=login");
		Cookie session = signedIn.getCookie("SESSION") != null ? signedIn.getCookie("SESSION") : pending;

		// The replay passes once and issues the code.
		String location = mvc.perform(get(URI.create(signedIn.getRedirectedUrl())).cookie(session))
				.andReturn().getResponse().getRedirectedUrl();
		assertThat(location).startsWith(REDIRECT + "?code=");
		String code = URLDecoder.decode(UriComponentsBuilder.fromUriString(location).build().getQueryParams()
				.getFirst("code"), StandardCharsets.UTF_8);
		String idToken = JsonPath.read(exchange(code), "$.id_token");
		long authTime = ((Number) JsonPath.read(claims(idToken), "$.auth_time")).longValue();
		assertThat(authTime).isCloseTo(System.currentTimeMillis() / 1000, org.assertj.core.data.Offset.offset(30L));
	}

	@Test
	void accessTokensCarryTheLoginsAuthTimeAlsoAfterARefresh() throws Exception {
		String first = exchange(authorize(newUser().browser(), "openid profile"));
		long idAuthTime = ((Number) JsonPath.read(claims(JsonPath.read(first, "$.id_token")), "$.auth_time")).longValue();
		long accessAuthTime = ((Number) JsonPath.read(claims(JsonPath.read(first, "$.access_token")), "$.auth_time")).longValue();
		assertThat(accessAuthTime).isEqualTo(idAuthTime);

		Thread.sleep(1100); // a refresh a second later still reports the original login time
		String refreshed = refresh(JsonPath.read(first, "$.refresh_token"));
		assertThat(((Number) JsonPath.read(claims(JsonPath.read(refreshed, "$.access_token")), "$.auth_time")).longValue())
				.isEqualTo(idAuthTime);
	}

	@Test
	void rpInitiatedLogoutEndsTheSsoSessionEvenAfterTheRefreshTokenWasRevoked() throws Exception {
		Session s = newUser();
		String tokens = exchange(authorize(s.browser(), "openid profile"));
		String idToken = JsonPath.read(tokens, "$.id_token");
		String refreshToken = JsonPath.read(tokens, "$.refresh_token");
		// The product first revokes its refresh token (server side), then sends the browser to /connect/logout.
		mvc.perform(post("/oauth2/revoke").with(httpBasic(CLIENT, SECRET)).contentType(MediaType.APPLICATION_FORM_URLENCODED)
				.content("token=" + refreshToken + "&token_type_hint=refresh_token")).andExpect(status().isOk());

		String loggedOut = "http://127.0.0.1:8080/auth/logged-out";
		// SAS reads GET parameters from the raw query string (MockMvc .param() does not put them there).
		String location = mvc.perform(get(URI.create("/connect/logout?id_token_hint=" + idToken
						+ "&post_logout_redirect_uri=" + URLEncoder.encode(loggedOut, StandardCharsets.UTF_8)))
						.cookie(s.browser()))
				.andExpect(status().is3xxRedirection()).andReturn().getResponse().getRedirectedUrl();
		assertThat(location).startsWith(loggedOut);
		// The Auth session is gone: the next sign-in asks for the password again.
		mvc.perform(get("/account").cookie(s.browser())).andExpect(status().is3xxRedirection());
		mvc.perform(get(URI.create("/oauth2/authorize?response_type=code&client_id=" + CLIENT + "&redirect_uri=" + REDIRECT
						+ "&scope=openid&state=st1&code_challenge=" + s256(VERIFIER) + "&code_challenge_method=S256"))
						.cookie(s.browser()).accept(MediaType.TEXT_HTML))
				.andExpect(status().is3xxRedirection())
				.andExpect(result -> assertThat(result.getResponse().getRedirectedUrl()).endsWith("/login"));
	}

	@Test
	void authorizationCodeWorksOnce() throws Exception {
		String code = authorize(newUser().browser());
		exchange(code);
		token(SECRET, "grant_type", "authorization_code", "code", code, "redirect_uri", REDIRECT,
				"code_verifier", VERIFIER).andExpect(status().isBadRequest());
	}

	@Test
	void refreshRotatesAndTheOldRefreshTokenStopsWorking() throws Exception {
		Session s = newUser();
		String r1 = JsonPath.read(exchange(authorize(s.browser())), "$.refresh_token");

		String second = refresh(r1);
		String r2 = JsonPath.read(second, "$.refresh_token");
		assertThat(r2).isNotEqualTo(r1);
		assertThat((String) JsonPath.read(claims(JsonPath.read(second, "$.access_token")), "$.sub")).isEqualTo(s.uid());

		String third = refresh(r2);
		assertThat(third).contains("access_token");
		String r3 = JsonPath.read(third, "$.refresh_token");
		assertThat(refresh(r3)).contains("access_token");
	}

	@Test
	void reusingARotatedRefreshTokenRevokesTheWholeLogin() throws Exception {
		Session s = newUser();
		String r1 = JsonPath.read(exchange(authorize(s.browser())), "$.refresh_token");
		String r2 = JsonPath.read(refresh(r1), "$.refresh_token");

		// Within the grace period a duplicate is only refused (retry / overlapping request).
		assertThat(refresh(r1)).contains("invalid_grant");
		String r3 = JsonPath.read(refresh(r2), "$.refresh_token"); // immediate duplicate did not kill the login

		// Later, a rotated-away token means it leaked.
		jdbc.update("UPDATE rotated_refresh_tokens SET rotated_at = NOW(6) - INTERVAL 1 MINUTE");
		assertThat(refresh(r1)).as("leaked old token").contains("invalid_grant");
		assertThat(refresh(r3)).as("legit newest token dies with it").contains("invalid_grant");
		assertThat(jdbc.queryForList("SELECT detail FROM security_events WHERE user_id = ? AND type = 'TOKEN_REUSE'",
				String.class, s.uid())).as("the owner sees it on the account page").containsExactly("Mirattic Sync");
		assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM oauth2_authorization WHERE principal_name = ?",
				Integer.class, s.uid())).isZero();

		// Other logins of the same user are untouched.
		String other = JsonPath.read(exchange(authorize(s.browser())), "$.refresh_token");
		assertThat(refresh(other)).contains("access_token");
	}

	@Test
	void revokedRefreshTokenStopsWorking() throws Exception {
		String r = JsonPath.read(exchange(authorize(newUser().browser())), "$.refresh_token");
		mvc.perform(post("/oauth2/revoke").with(httpBasic(CLIENT, SECRET))
						.contentType("application/x-www-form-urlencoded")
						.content("token=" + r + "&token_type_hint=refresh_token"))
				.andExpect(status().isOk());
		assertThat(refresh(r)).contains("invalid_grant");
	}

	@Test
	void passwordChangeEndsRefresh() throws Exception {
		Session s = newUser();
		String r = JsonPath.read(exchange(authorize(s.browser())), "$.refresh_token");
		accounts.changePassword(s.uid(), "password-1", "password-2", null);
		assertThat(refresh(r)).contains("invalid_grant");
	}

	@Test
	void disabledAccountCannotRefreshOrExchangeCodes() throws Exception {
		Session s = newUser();
		String r = JsonPath.read(exchange(authorize(s.browser())), "$.refresh_token");
		String code = authorize(s.browser());
		jdbc.update("UPDATE users SET status = 'DISABLED' WHERE id = ?", s.uid());

		assertThat(refresh(r)).contains("invalid_grant");
		token(SECRET, "grant_type", "authorization_code", "code", code, "redirect_uri", REDIRECT,
				"code_verifier", VERIFIER).andExpect(status().isBadRequest());
	}

	@Test
	void tokensAreStoredOnlyAsHashes() throws Exception {
		Session s = newUser();
		String body = exchange(authorize(s.browser()));
		String refreshToken = JsonPath.read(body, "$.refresh_token");
		var row = jdbc.queryForMap("SELECT CAST(authorization_code_value AS CHAR) code, "
				+ "CAST(access_token_value AS CHAR) access, CAST(refresh_token_value AS CHAR) refresh, "
				+ "CAST(oidc_id_token_value AS CHAR) id FROM oauth2_authorization "
				+ "WHERE principal_name = ? AND refresh_token_value IS NOT NULL", s.uid());
		assertThat(row.values()).allSatisfy(v -> assertThat((String) v).startsWith("sha256:").hasSize(71));
		assertThat(row.get("refresh")).isNotEqualTo(refreshToken);
		assertThat(refresh(refreshToken)).contains("access_token");
	}

	@Test
	void replayedCodeRevokesTheTokensItIssued() throws Exception {
		String code = authorize(newUser().browser());
		String r = JsonPath.read(exchange(code), "$.refresh_token");
		token(SECRET, "grant_type", "authorization_code", "code", code, "redirect_uri", REDIRECT,
				"code_verifier", VERIFIER).andExpect(status().isBadRequest());
		assertThat(refresh(r)).contains("invalid_grant");
	}

	@Test
	void idTokenAndUserInfoCarryClaimsByScope() throws Exception {
		Session s = newUser();
		String body = exchange(authorize(s.browser(), "openid profile email"));
		String id = claims(JsonPath.read(body, "$.id_token"));
		assertThat((String) JsonPath.read(id, "$.name")).isEqualTo("C");
		assertThat((String) JsonPath.read(id, "$.email")).isEqualTo(s.email());
		assertThat((Boolean) JsonPath.read(id, "$.email_verified")).isFalse();

		String access = JsonPath.read(body, "$.access_token");
		accounts.changeDisplayName(s.uid(), "Renamed");
		String info = userInfo(access).andExpect(status().isOk()).andReturn().getResponse().getContentAsString();
		assertThat((String) JsonPath.read(info, "$.sub")).isEqualTo(s.uid());
		assertThat((String) JsonPath.read(info, "$.name")).as("live, not the ID token snapshot").isEqualTo("Renamed");
		assertThat((String) JsonPath.read(info, "$.email")).isEqualTo(s.email());

		String openidOnly = JsonPath.read(exchange(authorize(s.browser(), "openid")), "$.access_token");
		String minimal = userInfo(openidOnly).andExpect(status().isOk()).andReturn().getResponse().getContentAsString();
		assertThat(minimal).contains("sub").doesNotContain("name").doesNotContain("email");

		jdbc.update("UPDATE users SET status = 'DISABLED' WHERE id = ?", s.uid());
		userInfo(access).andExpect(status().isUnauthorized());
	}

	@Test
	void downscopedRefreshLimitsUserInfo() throws Exception {
		Session s = newUser();
		String r = JsonPath.read(exchange(authorize(s.browser(), "openid profile email")), "$.refresh_token");
		String narrowed = token(SECRET, "grant_type", "refresh_token", "refresh_token", r, "scope", "openid")
				.andExpect(status().isOk()).andReturn().getResponse().getContentAsString();
		String info = userInfo(JsonPath.read(narrowed, "$.access_token"))
				.andExpect(status().isOk()).andReturn().getResponse().getContentAsString();
		assertThat(info).contains(s.uid()).doesNotContain("name").doesNotContain("email");
	}

	@Test
	void concurrentRefreshesWithTheSameTokenHaveOneWinnerAndNoFalseReuse() throws Exception {
		Session s = newUser();
		String r1 = JsonPath.read(exchange(authorize(s.browser())), "$.refresh_token");
		// Two requests both read the authorization with r1 before either saves (what SAS does per request).
		OAuth2Authorization a = authorizations.findByToken(r1, OAuth2TokenType.REFRESH_TOKEN);
		OAuth2Authorization b = authorizations.findByToken(r1, OAuth2TokenType.REFRESH_TOKEN);
		Instant now = Instant.now();
		authorizations.save(OAuth2Authorization.from(a)
				.refreshToken(new OAuth2RefreshToken("winner-" + s.uid(), now, now.plusSeconds(3600))).build());
		assertThatThrownBy(() -> authorizations.save(OAuth2Authorization.from(b)
				.refreshToken(new OAuth2RefreshToken("loser-" + s.uid(), now, now.plusSeconds(3600))).build()))
				.isInstanceOf(OAuth2AuthenticationException.class);

		assertThat(refresh("loser-" + s.uid())).contains("invalid_grant");
		assertThat(refresh("winner-" + s.uid())).as("winner not treated as reused").contains("access_token");
	}

	@Test
	void overlappingRefreshAfterTheWinnerSavedDoesNotKillTheWinner() throws Exception {
		Session s = newUser();
		String r1 = JsonPath.read(exchange(authorize(s.browser())), "$.refresh_token");
		String r2 = JsonPath.read(refresh(r1), "$.refresh_token"); // winner done
		assertThat(refresh(r1)).as("late duplicate").contains("invalid_grant");
		assertThat(refresh(r2)).contains("access_token");
	}

	@Test
	void anotherClientCannotTriggerReuseRevocation() throws Exception {
		Session s = newUser();
		String r1 = JsonPath.read(exchange(authorize(s.browser())), "$.refresh_token");
		String r2 = JsonPath.read(refresh(r1), "$.refresh_token");
		jdbc.update("UPDATE rotated_refresh_tokens SET rotated_at = NOW(6) - INTERVAL 1 MINUTE");
		mvc.perform(post("/oauth2/revoke").with(httpBasic("mirattic-flow", "dev-flow-secret"))
						.contentType("application/x-www-form-urlencoded")
						.content("token=" + r1 + "&token_type_hint=refresh_token"))
				.andExpect(status().isOk());
		assertThat(refresh(r2)).contains("access_token");
	}

	@Test
	void stateLookupBypassesHashing() {
		OAuth2Authorization saved = OAuth2Authorization.withRegisteredClient(clients.findByClientId(CLIENT))
				.id(UUID.randomUUID().toString())
				.principalName("state-test")
				.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
				.attribute(OAuth2ParameterNames.STATE, "consent-state-1")
				.build();
		authorizations.save(saved);
		OAuth2TokenType state = new OAuth2TokenType(OAuth2ParameterNames.STATE);
		assertThat(authorizations.findByToken("consent-state-1", state)).isNotNull();
		assertThat(authorizations.findByToken("consent-state-1", null)).isNotNull();
		authorizations.remove(saved);
	}

	ResultActions userInfo(String accessToken) throws Exception {
		return mvc.perform(get("/userinfo").header("Authorization", "Bearer " + accessToken));
	}
}
