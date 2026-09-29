package com.mirattic.auth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.hamcrest.Matchers.containsString;
import static org.mockito.Mockito.after;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.timeout;
import static org.mockito.Mockito.verify;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.view;

import com.jayway.jsonpath.JsonPath;
import com.mirattic.auth.account.AccountException;
import java.nio.charset.StandardCharsets;
import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.test.web.servlet.ResultActions;
import jakarta.servlet.http.Cookie;

class AccountFlowTest extends IntegrationTest {


	@Test
	void signupThenLoginThenAuthorizationCodeIssuesTokensWithUidAsSub() throws Exception {
		String email = email();
		mvc.perform(post("/signup").with(csrf())
						.param("email", " " + email.toUpperCase() + " ")
						.param("password", "correct horse")
						.param("displayName", "  기석  "))
				.andExpect(redirectedUrl("/login?signup"));
		String uid = jdbc.queryForObject("SELECT user_id FROM user_identities WHERE subject = ?", String.class, email);
		assertThat(accounts.find(uid).displayName()).isEqualTo("기석");

		String body = exchange(authorize(login(email, "correct horse")));

		String idToken = JsonPath.read(body, "$.id_token");
		String accessToken = JsonPath.read(body, "$.access_token");
		String idClaims = claims(idToken);
		String accessClaims = claims(accessToken);
		assertThat((String) JsonPath.read(idClaims, "$.sub")).isEqualTo(uid);
		assertThat((String) JsonPath.read(idClaims, "$.nonce")).isEqualTo("n1");
		assertThat((String) JsonPath.read(idClaims, "$.iss")).isEqualTo("http://localhost:9000");
		assertThat((String) JsonPath.read(accessClaims, "$.sub")).isEqualTo(uid);
		assertThat((String) JsonPath.read(accessClaims, "$.aud")).isEqualTo(CLIENT);
		assertThat((String) JsonPath.read(body, "$.refresh_token")).isNotBlank();
	}

	ResultActions signupFrom(String ip, String email) throws Exception {
		return mvc.perform(post("/signup").with(csrf()).with(r -> {
			r.setRemoteAddr(ip);
			return r;
		}).param("email", email).param("password", "password-1").param("displayName", "N"));
	}

	@Test
	void oneSignupPerNetworkPerDay() throws Exception {
		String taken = email();
		signup(taken, "password-1", "T");
		// A failed signup (duplicate email) rolls back and does not use the slot.
		signupFrom("198.51.100.7", taken).andExpect(content().string(containsString("이미 가입된 이메일입니다.")));
		signupFrom("198.51.100.7", email()).andExpect(redirectedUrl("/login?signup"));
		signupFrom("198.51.100.7", email()).andExpect(content().string(containsString("하루에 한 계정만")));
		signupFrom("198.51.100.8", email()).andExpect(redirectedUrl("/login?signup"));
		// IPv6: the whole /64 is one network.
		signupFrom("2001:db8:aa:1::1", email()).andExpect(redirectedUrl("/login?signup"));
		signupFrom("2001:db8:aa:1::2", email()).andExpect(content().string(containsString("하루에 한 계정만")));

		jdbc.update("UPDATE signup_ips SET last_signup_at = NOW(6) - INTERVAL 25 HOUR");
		signupFrom("198.51.100.7", email()).andExpect(redirectedUrl("/login?signup"));
		assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM signup_ips WHERE ip_hash LIKE '198%'", Integer.class))
				.as("only hashes stored").isZero();
	}

	@Test
	void signupRejectsDuplicatesAndBadInputWithoutPartialRows() throws Exception {
		String email = email();
		signup(email, "password1", "A");
		int users = jdbc.queryForObject("SELECT COUNT(*) FROM users", Integer.class);

		assertThatThrownBy(() -> signup(email.toUpperCase(), "password1", "B"))
				.isInstanceOf(AccountException.class).hasMessageContaining("이미 가입");
		assertThatThrownBy(() -> signup("not-an-email", "password1", "B")).isInstanceOf(AccountException.class);
		assertThatThrownBy(() -> signup(email(), "short", "B")).isInstanceOf(AccountException.class);
		assertThatThrownBy(() -> signup(email(), "가".repeat(25), "B")) // 75 bytes > BCrypt's 72
				.isInstanceOf(AccountException.class);
		assertThatThrownBy(() -> signup(email(), "password1", "   ")).isInstanceOf(AccountException.class);
		assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM users", Integer.class)).isEqualTo(users);

		signupFrom("198.51.100.99", email)
				.andExpect(status().isOk())
				.andExpect(view().name("signup"))
				.andExpect(content().string(containsString("이미 가입된 이메일입니다.")));
	}

	@Test
	void passwordResetHidesUnknownEmailsAndIsOneTime() throws Exception {
		Mockito.reset(mailSender);
		String email = email();
		String uid = signup(email, "old-password", "R");
		jdbc.update("INSERT INTO oauth2_authorization (id, registered_client_id, principal_name, authorization_grant_type)"
				+ " VALUES (?, 'x', ?, 'authorization_code')", UUID.randomUUID().toString(), uid);

		String unknown = mvc.perform(post("/password/reset").with(csrf()).param("email", email()))
				.andExpect(status().isOk()).andReturn().getResponse().getContentAsString();
		verify(mailSender, after(300).never()).send(Mockito.any(SimpleMailMessage.class));
		String known = mvc.perform(post("/password/reset").with(csrf()).param("email", email))
				.andExpect(status().isOk()).andReturn().getResponse().getContentAsString();
		assertThat(known).isEqualTo(unknown);

		ArgumentCaptor<SimpleMailMessage> mail = ArgumentCaptor.forClass(SimpleMailMessage.class);
		verify(mailSender, timeout(2000)).send(mail.capture());
		assertThat(mail.getValue().getTo()).containsExactly(email);
		Matcher m = Pattern.compile("token=([A-Za-z0-9_-]+)").matcher(mail.getValue().getText());
		assertThat(m.find()).isTrue();
		String token = m.group(1);
		assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM password_reset_tokens WHERE token_hash = ?",
				Integer.class, token)).as("raw token must not be stored").isZero();

		mvc.perform(post("/password/reset/confirm").with(csrf()).param("token", token).param("password", "new-password"))
				.andExpect(redirectedUrl("/login?reset"));
		loginFails(email, "old-password");
		login(email, "new-password");
		assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM oauth2_authorization WHERE principal_name = ?",
				Integer.class, uid)).as("reset ends OAuth authorizations").isZero();

		mvc.perform(post("/password/reset/confirm").with(csrf()).param("token", token).param("password", "third-password"))
				.andExpect(view().name("reset-confirm"));
		login(email, "new-password");
	}

	@Test
	void resetMailIsSentAtMostOncePerMinutePerAccount() throws Exception {
		Mockito.reset(mailSender);
		String email = email();
		signup(email, "password-1", "M");
		accounts.requestPasswordReset(email);
		verify(mailSender, timeout(2000)).send(Mockito.any(SimpleMailMessage.class));
		accounts.requestPasswordReset(email);
		accounts.requestPasswordReset(email);
		verify(mailSender, after(500).times(1)).send(Mockito.any(SimpleMailMessage.class));
	}

	@Test
	void concurrentResetRequestsSendOneMail() throws Exception {
		Mockito.reset(mailSender);
		String email = email();
		signup(email, "password-1", "P");
		for (int i = 0; i < 8; i++) {
			accounts.requestPasswordReset(email); // @Async: these run in parallel
		}
		verify(mailSender, after(2000).times(1)).send(Mockito.any(SimpleMailMessage.class));
	}

	@Test
	void expiredResetTokenIsRejected() {
		String uid = signup(email(), "old-password", "E");
		jdbc.update("INSERT INTO password_reset_tokens (id, user_id, token_hash, expires_at, created_at) "
				+ "VALUES (UUID(), ?, SHA2('expired-token', 256), NOW(6) - INTERVAL 1 SECOND, NOW(6))", uid);
		assertThatThrownBy(() -> accounts.resetPassword("expired-token", "new-password"))
				.isInstanceOf(AccountException.class);
	}

	@Test
	void accountPageRequiresLoginAndChangesNameAndPassword() throws Exception {
		mvc.perform(get("/account")).andExpect(redirectedUrl("/login"));

		String email = email();
		String uid = signup(email, "password-1", "Before");
		Cookie session = login(email, "password-1");

		mvc.perform(get("/account").cookie(session))
				.andExpect(status().isOk())
				.andExpect(content().string(org.hamcrest.Matchers.containsString(uid)));
		mvc.perform(post("/account/name").with(csrf()).cookie(session).param("displayName", "After"))
				.andExpect(redirectedUrl("/account?saved"));
		assertThat(accounts.find(uid).displayName()).isEqualTo("After");

		mvc.perform(post("/account/password").with(csrf()).cookie(session)
						.param("currentPassword", "wrong-pass").param("password", "password-2"))
				.andExpect(view().name("account"));
		mvc.perform(post("/account/password").with(csrf()).cookie(session)
						.param("currentPassword", "password-1").param("password", "password-2"))
				.andExpect(redirectedUrl("/account?password"));
		loginFails(email, "password-1");
		login(email, "password-2");

		jdbc.update("INSERT INTO password_reset_tokens (id, user_id, token_hash, expires_at, created_at) "
				+ "VALUES (UUID(), ?, SHA2(?, 256), NOW(6) + INTERVAL 30 MINUTE, NOW(6))", uid, "pending-" + uid);
		mvc.perform(post("/account/password").with(csrf()).cookie(session)
						.param("currentPassword", "password-2").param("password", "password-3"))
				.andExpect(redirectedUrl("/account?password"));
		assertThatThrownBy(() -> accounts.resetPassword("pending-" + uid, "attacker-pass"))
				.as("password change kills outstanding reset links").isInstanceOf(AccountException.class);

		mvc.perform(post("/account/name").cookie(session).param("displayName", "NoCsrf"))
				.andExpect(status().isForbidden());
	}

	@Test
	void browserSessionsLiveInTheDbAndAPasswordChangeEndsTheOtherOnes() throws Exception {
		String email = email();
		String uid = signup(email, "password-1", "S");
		Cookie laptop = login(email, "password-1");
		Cookie phone = login(email, "password-1");
		assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM SPRING_SESSION WHERE PRINCIPAL_NAME = ?",
				Integer.class, uid)).isEqualTo(2);

		mvc.perform(post("/account/password").with(csrf()).cookie(laptop)
						.param("currentPassword", "password-1").param("password", "password-2"))
				.andExpect(redirectedUrl("/account?password"));
		mvc.perform(get("/account").cookie(laptop)).andExpect(status().isOk());
		mvc.perform(get("/account").cookie(phone)).andExpect(redirectedUrl("/login"));

		// A reset (not signed in) ends every session.
		String token = "reset-" + uid;
		jdbc.update("INSERT INTO password_reset_tokens (id, user_id, token_hash, expires_at, created_at) "
				+ "VALUES (UUID(), ?, SHA2(?, 256), NOW(6) + INTERVAL 30 MINUTE, NOW(6) - INTERVAL 5 MINUTE)", uid, token);
		accounts.resetPassword(token, "password-3");
		mvc.perform(get("/account").cookie(laptop)).andExpect(redirectedUrl("/login"));
	}

	@Test
	void disabledAccountCannotLogInOrRequestReset() throws Exception {
		Mockito.reset(mailSender);
		String email = email();
		String uid = signup(email, "password-1", "D");
		jdbc.update("UPDATE users SET status = 'DISABLED' WHERE id = ?", uid);

		loginFails(email, "password-1");
		loginFails(email, "wrong-password");
		accounts.requestPasswordReset(email);
		verify(mailSender, after(300).never()).send(Mockito.any(SimpleMailMessage.class));
	}

	@Test
	void resetPagesSendNoReferrer() throws Exception {
		mvc.perform(get("/password/reset/confirm?token=abc"))
				.andExpect(status().isOk())
				.andExpect(org.springframework.test.web.servlet.result.MockMvcResultMatchers.header()
						.string("Referrer-Policy", "no-referrer"));
	}
}
