package com.mirattic.auth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;

import com.mirattic.auth.account.AccountService;
import java.nio.charset.StandardCharsets;
import java.util.UUID;
import org.hamcrest.Matchers;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;

/** Production default: social sign-in only. The email routes are closed even to someone who knows the URL. */
@TestPropertySource(properties = "auth.email-login=false")
class EmailLoginOffTest extends IntegrationTest {

	@Autowired
	MockMvc mvc;

	@Autowired
	AccountService accounts;

	@Test
	void loginPageOffersSocialOnly() throws Exception {
		String page = mvc.perform(get("/login")).andReturn().getResponse().getContentAsString(StandardCharsets.UTF_8);
		assertThat(page).contains("/oauth2/authorization/kakao", "/oauth2/authorization/naver",
				"/oauth2/authorization/google");
		assertThat(page).doesNotContain("id=\"password\"", "/signup", "/password/reset");
	}

	@Test
	void emailRoutesAreClosed() throws Exception {
		String email = UUID.randomUUID() + "@example.com";
		accounts.signup(email, "correct horse battery", "Off", "127.0.0.1");
		// The right password does not sign in: no session, back to the login page.
		var login = mvc.perform(post("/login").with(csrf()).param("username", email)
				.param("password", "correct horse battery"))
				.andExpect(header().string("Location", Matchers.endsWith("/login"))).andReturn();
		assertThat(login.getRequest().getSession(false) == null
				|| login.getRequest().getSession(false).getAttribute("SPRING_SECURITY_CONTEXT") == null).isTrue();
		for (String path : new String[] {"/signup", "/password/reset", "/password/reset/confirm?token=x"}) {
			mvc.perform(get(path)).andExpect(header().string("Location", Matchers.endsWith("/login")));
		}
		mvc.perform(post("/signup").with(csrf()).param("email", "new-" + email).param("password", "correct horse battery")
				.param("displayName", "New")).andExpect(header().string("Location", Matchers.endsWith("/login")));
		mvc.perform(post("/password/reset").with(csrf()).param("email", email))
				.andExpect(header().string("Location", Matchers.endsWith("/login")));
	}
}
