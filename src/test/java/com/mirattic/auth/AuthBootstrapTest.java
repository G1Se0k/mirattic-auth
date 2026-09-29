package com.mirattic.auth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.hasKey;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;

class AuthBootstrapTest extends IntegrationTest {

	@Autowired UserDetailsService userDetails;
	@Autowired PasswordEncoder passwordEncoder;

	@Test
	void discoveryAdvertisesIssuerAndEndpoints() throws Exception {
		mvc.perform(get("/.well-known/openid-configuration"))
				.andExpect(status().isOk())
				.andExpect(jsonPath("$.issuer").value("http://localhost:9000"))
				.andExpect(jsonPath("$.jwks_uri").value("http://localhost:9000/oauth2/jwks"))
				.andExpect(jsonPath("$.code_challenge_methods_supported[0]").value("S256"));
	}

	@Test
	void jwksPublishesOnlyThePublicRsaKey() throws Exception {
		mvc.perform(get("/oauth2/jwks"))
				.andExpect(status().isOk())
				.andExpect(jsonPath("$.keys", hasSize(1)))
				.andExpect(jsonPath("$.keys[0].kty").value("RSA"))
				.andExpect(jsonPath("$.keys[0].kid").isString())
				.andExpect(jsonPath("$.keys[0]", not(hasKey("d"))));
	}

	@Test
	void healthIsPublicAndAuthorizeSendsBrowsersToLogin() throws Exception {
		mvc.perform(get("/actuator/health")).andExpect(status().isOk());
		// Authorization params must be in the query string for GET.
		mvc.perform(get("/oauth2/authorize?response_type=code&client_id=mirattic-dev"
						+ "&redirect_uri=http://127.0.0.1:8081/callback&scope=openid"
						+ "&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256")
						.accept(MediaType.TEXT_HTML))
				.andExpect(status().is3xxRedirection())
				.andExpect(redirectedUrl("/login"));
	}

	@Test
	void localLoginResolvesToGlobalUidNotEmail() {
		String uid = "11111111-1111-1111-1111-111111111111";
		jdbc.update("INSERT INTO users VALUES (?, 'Tester', 'ACTIVE', NOW(6), NOW(6))", uid);
		jdbc.update("INSERT INTO user_identities VALUES (UUID(), ?, 'LOCAL', 'a@mirattic.com', 'a@mirattic.com', ?, NOW(6), NOW(6))",
				uid, passwordEncoder.encode("pw"));

		UserDetails user = userDetails.loadUserByUsername("  A@Mirattic.com ");
		assertThat(user.getUsername()).isEqualTo(uid);
		assertThat(user.isEnabled()).isTrue();

		jdbc.update("UPDATE users SET status = 'DISABLED' WHERE id = ?", uid);
		assertThat(userDetails.loadUserByUsername("a@mirattic.com").isEnabled()).isFalse();

		assertThatThrownBy(() -> userDetails.loadUserByUsername("nobody@mirattic.com"))
				.isInstanceOf(UsernameNotFoundException.class);
	}
}
