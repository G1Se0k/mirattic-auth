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
import java.security.MessageDigest;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;
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
	void resetMailIsSentAtMostOncePerDayPerAccount() throws Exception {
		Mockito.reset(mailSender);
		String email = email();
		signup(email, "password-1", "M");
		accounts.requestPasswordReset(email);
		verify(mailSender, timeout(2000)).send(Mockito.any(SimpleMailMessage.class));
		accounts.requestPasswordReset(email);
		jdbc.update("UPDATE password_reset_tokens t JOIN user_identities i ON i.user_id = t.user_id "
				+ "SET t.created_at = NOW(6) - INTERVAL 23 HOUR WHERE i.subject = ?", email);
		accounts.requestPasswordReset(email);
		verify(mailSender, after(500).times(1)).send(Mockito.any(SimpleMailMessage.class));

		jdbc.update("UPDATE password_reset_tokens t JOIN user_identities i ON i.user_id = t.user_id "
				+ "SET t.created_at = NOW(6) - INTERVAL 25 HOUR WHERE i.subject = ?", email);
		accounts.requestPasswordReset(email);
		verify(mailSender, timeout(2000).times(2)).send(Mockito.any(SimpleMailMessage.class));
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
	void devicesListsBrowsersAndAppsAndEndsOneAtATime() throws Exception {
		String email = email();
		String uid = signup(email, "password-1", "D");
		Cookie laptop = login(email, "password-1");
		Cookie phone = mvc.perform(post("/login").with(csrf()).param("username", email).param("password", "password-1")
						.header("User-Agent", "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 "
								+ "(KHTML, like Gecko) Version/18.0 Mobile/15E148 Safari/604.1"))
				.andExpect(redirectedUrl("/")).andReturn().getResponse().getCookie("SESSION");
		String refresh = JsonPath.read(exchange(authorize(laptop)), "$.refresh_token");
		String appId = jdbc.queryForObject("SELECT id FROM oauth2_authorization WHERE principal_name = ?", String.class, uid);

		String page = mvc.perform(get("/account").cookie(laptop)).andExpect(status().isOk())
				.andReturn().getResponse().getContentAsString(StandardCharsets.UTF_8);
		assertThat(page).contains("Safari · iPhone", "Mirattic Sync", "이 브라우저", "value=\"" + appId + "\"")
				.doesNotContain(sessionId(phone), sessionId(laptop));
		Matcher ids = Pattern.compile("name=\"id\" value=\"([0-9a-f]{64})\"").matcher(page);
		assertThat(ids.find()).isTrue(); // the phone: this browser has no button
		String phoneId = ids.group(1);
		assertThat(ids.find()).isFalse();

		// Someone else can't end them.
		String otherEmail = email();
		signup(otherEmail, "password-1", "O");
		Cookie other = login(otherEmail, "password-1");
		for (String id : new String[] {phoneId, appId}) {
			mvc.perform(post("/account/devices/end").with(csrf()).cookie(other).param("id", id))
					.andExpect(redirectedUrl("/account?ended#devices"));
		}
		mvc.perform(get("/account").cookie(phone)).andExpect(status().isOk());
		assertThat(refresh(refresh)).contains("refresh_token");
		String rotated = jdbc.queryForObject("SELECT id FROM oauth2_authorization WHERE principal_name = ?", String.class, uid);

		mvc.perform(post("/account/devices/end").with(csrf()).cookie(laptop).param("id", phoneId));
		mvc.perform(get("/account").cookie(phone)).andExpect(redirectedUrl("/login"));
		mvc.perform(post("/account/devices/end").with(csrf()).cookie(laptop).param("id", rotated));
		assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM oauth2_authorization WHERE principal_name = ?",
				Integer.class, uid)).isZero();
		// This browser is ended by logging out, not from the list.
		String laptopId = HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
				.digest(sessionId(laptop).getBytes(StandardCharsets.UTF_8)));
		mvc.perform(post("/account/devices/end").with(csrf()).cookie(laptop).param("id", laptopId));
		mvc.perform(get("/account").cookie(laptop)).andExpect(status().isOk());
	}

	@Test
	void deletingTheAccountDeletesProductDataFirstThenEverythingThatSignsIn() throws Exception {
		SocialStub.DELETION.clear();
		String email = email();
		String uid = signup(email, "password-1", "Del");
		Cookie session = login(email, "password-1");
		Cookie other = login(email, "password-1");
		String refresh = JsonPath.read(exchange(authorize(session)), "$.refresh_token");
		String pendingCode = authorize(session);
		SocialStub.DELETIONS.clear();
		// While the products delete, the account is fenced: no code exchange (a product profile made again behind
		// its 204), no sign-in.
		List<String> during = new CopyOnWriteArrayList<>();
		SocialStub.duringDeletion = () -> {
			try {
				during.add(jdbc.queryForObject("SELECT status FROM users WHERE id = ?", String.class, uid));
				during.add(token(SECRET, "grant_type", "authorization_code", "code", pendingCode, "redirect_uri", REDIRECT,
						"code_verifier", VERIFIER).andReturn().getResponse().getContentAsString());
			} catch (Exception e) {
				during.add(e.toString());
			}
		};
		try {
			mvc.perform(post("/account/delete").with(csrf()).cookie(session).param("confirm", "true"))
					.andExpect(redirectedUrl("/login?deleted"));
		} finally {
			SocialStub.duringDeletion = () -> { };
		}
		assertThat(during.get(0)).isEqualTo("DISABLED");
		assertThat(during.get(1)).contains("invalid_grant");

		// Flow first (it may refuse), then Sync; each gets its own one-minute order for this user.
		assertThat(SocialStub.DELETIONS).hasSize(2);
		assertThat(SocialStub.DELETIONS.get(0)).startsWith("flow ");
		assertThat(SocialStub.DELETIONS.get(1)).startsWith("sync ");
		String order = claims(SocialStub.DELETIONS.get(0).substring(5));
		assertThat((String) JsonPath.read(order, "$.sub")).isEqualTo(uid);
		assertThat((String) JsonPath.read(order, "$.aud")).isEqualTo("mirattic-flow");
		assertThat((String) JsonPath.read(order, "$.purpose")).isEqualTo("account_deletion");
		assertThat(order).doesNotContain("scope"); // never usable as an access token
		assertThat(((Number) JsonPath.read(order, "$.exp")).longValue() - ((Number) JsonPath.read(order, "$.iat")).longValue())
				.isEqualTo(60);
		assertThat((String) JsonPath.read(claims(SocialStub.DELETIONS.get(1).substring(5)), "$.aud"))
				.isEqualTo("mirattic-sync");

		assertThat(jdbc.queryForObject("SELECT status FROM users WHERE id = ?", String.class, uid)).isEqualTo("DELETED");
		assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM user_identities WHERE user_id = ?", Integer.class, uid)).isZero();
		assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM security_events WHERE user_id = ?", Integer.class, uid)).isZero();
		mvc.perform(get("/account").cookie(session)).andExpect(redirectedUrl("/login"));
		mvc.perform(get("/account").cookie(other)).andExpect(redirectedUrl("/login"));
		assertThat(refresh(refresh)).contains("invalid_grant");
		loginFails(email, "password-1");
		// The email is free again: a new, unrelated account.
		assertThat(signup(email, "password-1", "New")).isNotEqualTo(uid);
	}

	@Test
	void aProductThatRefusesOrFailsStopsTheDeletion() throws Exception {
		String email = email();
		String uid = signup(email, "password-1", "Keep");
		Cookie session = login(email, "password-1");
		try {
			SocialStub.DELETION.put("flow", Map.entry(409, "{\"message\":\"혼자 소유한 워크스페이스가 있습니다.\"}"));
			SocialStub.DELETIONS.clear();
			mvc.perform(post("/account/delete").with(csrf()).cookie(session).param("confirm", "true"))
					.andExpect(status().isOk())
					.andExpect(content().string(containsString("Mirattic Flow에서 먼저 정리할 것이 있습니다: 혼자 소유한 워크스페이스가 있습니다.")));
			assertThat(SocialStub.DELETIONS).hasSize(1); // Sync untouched

			SocialStub.DELETION.put("flow", Map.entry(204, ""));
			SocialStub.DELETION.put("sync", Map.entry(500, "{}"));
			mvc.perform(post("/account/delete").with(csrf()).cookie(session).param("confirm", "true"))
					.andExpect(content().string(containsString("Mirattic Sync에 연결하지 못해")));
			// Only 204 confirms: a 200 or 202 (not done), or a redirect (a gateway / login page) is not a deletion.
			for (int status : new int[] {200, 202, 302}) {
				SocialStub.DELETION.put("sync", Map.entry(status, "{}"));
				mvc.perform(post("/account/delete").with(csrf()).cookie(session).param("confirm", "true"))
						.andExpect(content().string(containsString("Mirattic Sync에 연결하지 못해")));
			}
		} finally {
			SocialStub.DELETION.clear();
		}
		// A failed deletion lifts the fence.
		assertThat(jdbc.queryForObject("SELECT status FROM users WHERE id = ?", String.class, uid)).isEqualTo("ACTIVE");
		mvc.perform(get("/account").cookie(session)).andExpect(status().isOk());
		login(email, "password-1");

		// One deletion of an account at a time: while one runs (DISABLED), another browser's request is signed out
		// before it can start a second (ActiveAccountFilter; AccountDeletion also refuses a non-ACTIVE account).
		Cookie other = login(email, "password-1");
		jdbc.update("UPDATE users SET status = 'DISABLED' WHERE id = ?", uid);
		SocialStub.DELETIONS.clear();
		mvc.perform(post("/account/delete").with(csrf()).cookie(other).param("confirm", "true"))
				.andExpect(redirectedUrl("/login"));
		assertThat(SocialStub.DELETIONS).isEmpty();
		jdbc.update("UPDATE users SET status = 'ACTIVE' WHERE id = ?", uid);

		// No confirmation: nothing is asked of the products.
		SocialStub.DELETIONS.clear();
		mvc.perform(post("/account/delete").with(csrf()).cookie(session))
				.andExpect(content().string(containsString("탈퇴 확인에 체크해주세요")));
		assertThat(SocialStub.DELETIONS).isEmpty();
	}

	@Test
	void theSecurityLogShowsSignInsFailuresPasswordChangesAndSignOutsToTheOwnerOnly() throws Exception {
		String email = email();
		String uid = signup(email, "password-1", "Log");
		Cookie session = login(email, "password-1");
		Cookie phone = mvc.perform(post("/login").with(csrf()).param("username", email).param("password", "password-1")
						.header("User-Agent", "Mozilla/5.0 (Linux; Android 15) AppleWebKit/537.36 Chrome/140.0 Mobile Safari/537.36"))
				.andReturn().getResponse().getCookie("SESSION");
		mvc.perform(post("/login").with(csrf()).param("username", " " + email.toUpperCase() + " ")
				.param("password", "wrong-password").header("User-Agent", "Mozilla/5.0 (Windows NT 10.0) Firefox/140.0"))
				.andExpect(redirectedUrl("/login?error"));
		loginFails("nobody-" + email, "wrong-password"); // unknown email: nothing recorded, no error
		mvc.perform(post("/account/password").with(csrf()).cookie(session)
				.param("currentPassword", "password-1").param("password", "password-2"));
		// The password change already ended the phone's session; a sign-out of a live device is logged too.
		Cookie tablet = login(email, "password-2");
		String page = mvc.perform(get("/account").cookie(tablet)).andReturn().getResponse()
				.getContentAsString(StandardCharsets.UTF_8);
		Matcher other = Pattern.compile("name=\"id\" value=\"([0-9a-f]{64})\"").matcher(page);
		assertThat(other.find()).isTrue();
		mvc.perform(post("/account/devices/end").with(csrf()).cookie(tablet).param("id", other.group(1)));

		assertThat(jdbc.queryForList("SELECT CONCAT(type, ':', COALESCE(detail, '')) FROM security_events "
				+ "WHERE user_id = ? ORDER BY id", String.class, uid)).containsExactly(
				"SIGN_IN:이메일 · 알 수 없는 브라우저", "SIGN_IN:이메일 · Chrome · Android",
				"SIGN_IN_FAILED:Firefox · Windows", "PASSWORD_CHANGED:", "SIGN_IN:이메일 · 알 수 없는 브라우저",
				"DEVICE_SIGNED_OUT:알 수 없는 브라우저");
		mvc.perform(get("/account").cookie(tablet)).andExpect(content().string(containsString("최근 보안 활동")))
				.andExpect(content().string(containsString("잘못된 비밀번호로 로그인 시도")))
				.andExpect(content().string(containsString("Firefox · Windows")));
		assertThat(phone).isNotNull();
	}

	@Test
	void aSessionOfAnAccountThatIsNoLongerActiveIsSignedOut() throws Exception {
		String email = email();
		String uid = signup(email, "password-1", "Fence");
		Cookie session = login(email, "password-1");
		mvc.perform(get("/account").cookie(session)).andExpect(status().isOk());
		// e.g. a sign-in that finished just as the account was fenced for deletion
		jdbc.update("UPDATE users SET status = 'DISABLED' WHERE id = ?", uid);
		mvc.perform(get("/account").cookie(session)).andExpect(redirectedUrl("/login"));
		jdbc.update("UPDATE users SET status = 'ACTIVE' WHERE id = ?", uid);
		// Signed out for good, not just for that request; SSO asks for a sign-in too.
		mvc.perform(get("/account").cookie(session)).andExpect(redirectedUrl("/login"));
		Cookie sso = login(email, "password-1");
		jdbc.update("UPDATE users SET status = 'DELETED' WHERE id = ?", uid);
		mvc.perform(get(java.net.URI.create("/oauth2/authorize?response_type=code&client_id=" + CLIENT + "&redirect_uri="
						+ REDIRECT + "&scope=openid&state=s&code_challenge=" + s256(VERIFIER) + "&code_challenge_method=S256"))
						.cookie(sso).accept(org.springframework.http.MediaType.TEXT_HTML))
				.andExpect(redirectedUrl("/login"));
	}

	/** Spring Session's cookie is the base64 of the session id. */
	private static String sessionId(Cookie c) {
		return new String(Base64.getDecoder().decode(c.getValue()), StandardCharsets.UTF_8);
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
