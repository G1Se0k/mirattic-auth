package com.mirattic.auth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.authentication;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.jayway.jsonpath.JsonPath;
import jakarta.servlet.http.Cookie;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.FactorGrantedAuthority;
import org.springframework.security.crypto.password.PasswordEncoder;

class AdminTest extends IntegrationTest {

	static final String ADMIN_EMAIL = "admin@mirattic.test";

	@Autowired
	PasswordEncoder encoder;

	@BeforeEach
	void admin() {
		jdbc.update("INSERT IGNORE INTO users VALUES (?, 'Admin', 'ACTIVE', NOW(6), NOW(6))", ADMIN);
		jdbc.update("INSERT IGNORE INTO user_identities VALUES (UUID(), ?, 'LOCAL', ?, ?, ?, NOW(6), NOW(6))", ADMIN,
				ADMIN_EMAIL, ADMIN_EMAIL, encoder.encode("admin-password"));
	}

	private String page(Cookie session, String path) throws Exception {
		return mvc.perform(get(path).cookie(session)).andExpect(status().isOk()).andReturn().getResponse()
				.getContentAsString(StandardCharsets.UTF_8);
	}

	@Test
	void onlyTheAdminGetsIn() throws Exception {
		mvc.perform(get("/admin")).andExpect(redirectedUrl("/login"));
		String email = email();
		signup(email, "password-1", "Plain");
		Cookie user = login(email, "password-1");
		mvc.perform(get("/admin").cookie(user)).andExpect(status().isForbidden());
		mvc.perform(post("/admin/users/" + ADMIN + "/suspend").with(csrf()).cookie(user))
				.andExpect(status().isForbidden());
		Cookie admin = login(ADMIN_EMAIL, "admin-password");
		assertThat(page(admin, "/admin")).contains("최근 14일 가입", "앱 사용자");
		mvc.perform(get("/admin/users/not-a-uuid").cookie(admin)).andExpect(status().isNotFound());
	}

	@Test
	void searchFindsByEmailAndTheUserPageShowsProductDataReadWithAnOrder() throws Exception {
		String email = email();
		String uid = signup(email, "password-1", "검색대상");
		Cookie admin = login(ADMIN_EMAIL, "admin-password");
		assertThat(page(admin, "/admin?q=" + email)).contains("검색대상", "/admin/users/" + uid);
		assertThat(page(admin, "/admin?q=" + uid)).contains("검색대상");
		// LIKE wildcards are literal.
		assertThat(page(admin, "/admin?q=%25")).doesNotContain("검색대상");

		SocialStub.ADMIN_READS.clear();
		String user = page(admin, "/admin/users/" + uid);
		assertThat(user).contains(email, "LOCAL", "3&lt;b&gt;", "영희", "응답을 받지 못했습니다.");
		assertThat(user).doesNotContain("{bcrypt}");
		String sync = SocialStub.ADMIN_READS.stream().filter(r -> r.startsWith("sync ")).findFirst().orElseThrow();
		assertThat(sync).startsWith("sync /users/" + uid + " ");
		String order = claims(sync.substring(sync.lastIndexOf(' ') + 1));
		assertThat((String) JsonPath.read(order, "$.aud")).isEqualTo("mirattic-sync");
		assertThat((String) JsonPath.read(order, "$.sub")).isEqualTo(ADMIN);
		assertThat((String) JsonPath.read(order, "$.purpose")).isEqualTo("admin_read");
		assertThat(order).doesNotContain("scope");
	}

	@Test
	void suspendingEndsEverySignInUntilResumed() throws Exception {
		String email = email();
		String uid = signup(email, "password-1", "Suspend");
		Cookie session = login(email, "password-1");
		String refresh = JsonPath.read(exchange(authorize(session)), "$.refresh_token");
		Cookie admin = login(ADMIN_EMAIL, "admin-password");

		mvc.perform(post("/admin/users/" + uid + "/suspend").with(csrf()).cookie(admin))
				.andExpect(redirectedUrl("/admin/users/" + uid + "?suspended"));
		assertThat(jdbc.queryForObject("SELECT status FROM users WHERE id = ?", String.class, uid)).isEqualTo("SUSPENDED");
		mvc.perform(get("/account").cookie(session)).andExpect(redirectedUrl("/login"));
		assertThat(refresh(refresh)).contains("invalid_grant");
		loginFails(email, "password-1");
		// Twice: nothing changes.
		mvc.perform(post("/admin/users/" + uid + "/suspend").with(csrf()).cookie(admin))
				.andExpect(redirectedUrl("/admin/users/" + uid + "?unchanged"));

		mvc.perform(post("/admin/users/" + uid + "/resume").with(csrf()).cookie(admin))
				.andExpect(redirectedUrl("/admin/users/" + uid + "?resumed"));
		Cookie again = login(email, "password-1");
		assertThat(page(admin, "/admin/users/" + uid)).contains("관리자가 이용 정지", "관리자가 이용 정지 해제");

		mvc.perform(post("/admin/users/" + uid + "/sign-out").with(csrf()).cookie(admin))
				.andExpect(redirectedUrl("/admin/users/" + uid + "?signedOut"));
		mvc.perform(get("/account").cookie(again)).andExpect(redirectedUrl("/login"));
	}

	@Test
	void theAdminCannotSuspendThemselvesAndChangesNeedARecentSignIn() throws Exception {
		Cookie admin = login(ADMIN_EMAIL, "admin-password");
		mvc.perform(post("/admin/users/" + ADMIN + "/suspend").with(csrf()).cookie(admin))
				.andExpect(redirectedUrl("/admin/users/" + ADMIN + "?self"));
		assertThat(jdbc.queryForObject("SELECT status FROM users WHERE id = ?", String.class, ADMIN)).isEqualTo("ACTIVE");

		String uid = signup(email(), "password-1", "Stale");
		var old = new UsernamePasswordAuthenticationToken(ADMIN, null, List.of(
				FactorGrantedAuthority.withAuthority(FactorGrantedAuthority.PASSWORD_AUTHORITY)
						.issuedAt(Instant.now().minusSeconds(11 * 60)).build()));
		for (String action : new String[] {"suspend", "resume", "sign-out"}) {
			mvc.perform(post("/admin/users/" + uid + "/" + action).with(csrf()).with(authentication(old)))
					.andExpect(redirectedUrl("/login?reauth"));
		}
		assertThat(jdbc.queryForObject("SELECT status FROM users WHERE id = ?", String.class, uid)).isEqualTo("ACTIVE");
	}
}
