package com.mirattic.auth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestBuilders.formLogin;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import jakarta.servlet.http.Cookie;
import java.net.URI;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicInteger;
import com.mirattic.auth.account.AccountService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.mail.javamail.JavaMailSender;

import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.web.util.UriComponentsBuilder;
import org.testcontainers.mysql.MySQLContainer;

/** One MySQL container and one Spring context shared by every test class. */
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("local")
public abstract class IntegrationTest {

	static final MySQLContainer MYSQL = new MySQLContainer("mysql:8.4")
			.withUrlParam("preserveInstants", "true")
			.withUrlParam("connectionTimeZone", "UTC")
			.withUrlParam("forceConnectionTimeZoneToSession", "true");

	static {
		MYSQL.start();
	}

	@DynamicPropertySource
	static void properties(DynamicPropertyRegistry registry) throws Exception {
		registry.add("spring.datasource.url", MYSQL::getJdbcUrl);
		registry.add("spring.datasource.username", MYSQL::getUsername);
		registry.add("spring.datasource.password", MYSQL::getPassword);
		Path dir = Files.createTempDirectory("mirattic-auth-key");
		registry.add("auth.signing-key.path", () -> dir.resolve("key.jwk.json").toString());
		// Every test runs mid-rotation: a previous key is published too, so tokens must pick the current one.
		Files.writeString(dir.resolve("previous.jwk.json"),
				new com.nimbusds.jose.jwk.gen.RSAKeyGenerator(2048).keyIDFromThumbprint(true).generate().toJSONString());
		registry.add("auth.signing-key.previous-path", () -> dir.resolve("previous.jwk.json").toString());
		for (String provider : new String[] {"kakao", "naver"}) {
			String prefix = "spring.security.oauth2.client.provider." + provider;
			registry.add(prefix + ".authorization-uri", () -> "https://" + provider + ".test/authorize");
			registry.add(prefix + ".token-uri", () -> SocialStub.url("/token"));
			registry.add(prefix + ".user-info-uri", () -> SocialStub.url("/me"));
		}
		registry.add("spring.security.oauth2.client.provider.google.authorization-uri", () -> "https://google.test/authorize");
		registry.add("spring.security.oauth2.client.provider.google.token-uri", () -> SocialStub.url("/token"));
		registry.add("spring.security.oauth2.client.provider.google.user-info-uri", () -> SocialStub.url("/me"));
		registry.add("spring.security.oauth2.client.provider.google.jwk-set-uri", () -> SocialStub.url("/jwks"));
		registry.add("auth.account-deletion.flow-url", () -> SocialStub.url("/flow/delete"));
		registry.add("auth.account-deletion.sync-url", () -> SocialStub.url("/sync/delete"));
		// Every test logs in from 127.0.0.1; the limiter itself is covered by AuthRateLimitFilterTest.
		registry.add("auth.rate-limit-per-minute", () -> "100000");
	}

	@MockitoBean
	protected JavaMailSender mailSender;

	@Autowired
	protected MockMvc mvc;

	@Autowired
	protected JdbcTemplate jdbc;

	// Dev client from application-local.yml.
	protected static final String CLIENT = "mirattic-sync";
	protected static final String SECRET = "dev-sync-secret";
	protected static final String REDIRECT = "http://127.0.0.1:8080/auth/callback";
	protected static final String VERIFIER = "dBjftJeZ4CVP-mJ92K9qOVHGwVcRZa8uAmhPJ5lDSWk";

	private static final AtomicInteger IPS = new AtomicInteger();

	@Autowired
	protected AccountService accounts;

	/** Service signup from a fresh client IP (one signup per IP per day). */
	protected String signup(String email, String password, String displayName) {
		int n = IPS.incrementAndGet();
		return accounts.signup(email, password, displayName, "10." + (n >> 16 & 255) + "." + (n >> 8 & 255) + "." + (n & 255));
	}

	protected static String email() {
		return "u" + UUID.randomUUID().toString().substring(0, 8) + "@mirattic.com";
	}

	protected static String s256(String verifier) {
		try {
			return Base64.getUrlEncoder().withoutPadding().encodeToString(
					MessageDigest.getInstance("SHA-256").digest(verifier.getBytes(StandardCharsets.US_ASCII)));
		} catch (Exception e) {
			throw new IllegalStateException(e);
		}
	}

	/** Payload of a JWT as JSON. */
	protected static String claims(String jwt) {
		return new String(Base64.getUrlDecoder().decode(jwt.split("\\.")[1]), StandardCharsets.UTF_8);
	}

	/** Returns the Auth browser session cookie (Spring Session, stored in the DB). */
	protected Cookie login(String email, String password) throws Exception {
		MvcResult r = mvc.perform(formLogin("/login").user(email).password(password))
				.andExpect(redirectedUrl("/"))
				.andReturn();
		Cookie session = r.getResponse().getCookie("SESSION");
		assertThat(session).isNotNull();
		return session;
	}

	protected void loginFails(String email, String password) throws Exception {
		mvc.perform(formLogin("/login").user(email).password(password)).andExpect(redirectedUrl("/login?error"));
	}

	protected String authorize(Cookie session) throws Exception {
		return authorize(session, "openid profile");
	}

	/** /oauth2/authorize with state=st1, nonce=n1, PKCE S256; returns the code. */
	protected String authorize(Cookie session, String scope) throws Exception {
		return code(authorizeWith(scope, session));
	}

	/** /oauth2/authorize as {@link #authorize(Cookie, String)}, sending these cookies (session, device). */
	protected MockHttpServletResponse authorizeWith(String scope, Cookie... cookies) throws Exception {
		return mvc.perform(get(URI.create("/oauth2/authorize?response_type=code&client_id=" + CLIENT
						+ "&redirect_uri=" + REDIRECT + "&scope=" + scope.replace(" ", "%20") + "&state=st1&nonce=n1"
						+ "&code_challenge=" + s256(VERIFIER) + "&code_challenge_method=S256")).cookie(cookies))
				.andExpect(status().is3xxRedirection())
				.andReturn().getResponse();
	}

	protected static String code(MockHttpServletResponse authorized) {
		String location = authorized.getRedirectedUrl();
		assertThat(location).startsWith(REDIRECT + "?code=").contains("state=st1");
		return URLDecoder.decode(UriComponentsBuilder.fromUriString(location).build().getQueryParams().getFirst("code"),
				StandardCharsets.UTF_8);
	}

	/** POST /oauth2/token with client_secret_basic. Parameters must be in the form body. */
	protected ResultActions token(String secret, String... params) throws Exception {
		StringBuilder body = new StringBuilder();
		for (int i = 0; i < params.length; i += 2) {
			body.append(i == 0 ? "" : "&").append(params[i]).append('=')
					.append(URLEncoder.encode(params[i + 1], StandardCharsets.UTF_8));
		}
		return mvc.perform(post("/oauth2/token").with(httpBasic(CLIENT, secret))
				.contentType(MediaType.APPLICATION_FORM_URLENCODED).content(body.toString()));
	}

	protected String exchange(String code) throws Exception {
		return token(SECRET, "grant_type", "authorization_code", "code", code, "redirect_uri", REDIRECT,
				"code_verifier", VERIFIER)
				.andExpect(status().isOk())
				.andReturn().getResponse().getContentAsString();
	}

	protected String refresh(String refreshToken) throws Exception {
		return token(SECRET, "grant_type", "refresh_token", "refresh_token", refreshToken)
				.andReturn().getResponse().getContentAsString();
	}
}
