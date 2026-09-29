package com.mirattic.auth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.jayway.jsonpath.JsonPath;
import com.mirattic.auth.account.AccountService;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.test.web.servlet.ResultActions;

/** Confidential clients (client_secret_basic + PKCE), refresh rotation, revocation. docs/clients.md */
class OAuthClientTest extends IntegrationTest {

	@Autowired AccountService accounts;
	@Autowired OAuth2AuthorizationService authorizations;
	@Autowired RegisteredClientRepository clients;

	record Session(String uid, String email, MockHttpSession browser) {
	}

	Session newUser() throws Exception {
		String email = email();
		String uid = accounts.signup(email, "password-1", "C");
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

		assertThat(refresh(r1)).contains("invalid_grant");
		assertThat(refresh(r2)).contains("access_token");
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
		accounts.changePassword(s.uid(), "password-1", "password-2");
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
