package com.mirattic.auth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;

import jakarta.servlet.http.Cookie;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;

/** Korean, English, Japanese: ?lang=, the cookie, then the browser's Accept-Language. */
class LanguageTest extends IntegrationTest {

	@Autowired
	MockMvc mvc;

	String page(MockHttpServletRequestBuilder request) throws Exception {
		return mvc.perform(request).andReturn().getResponse().getContentAsString(StandardCharsets.UTF_8);
	}

	@Test
	void theBrowsersLanguageIsUsedUntilOneIsPicked() throws Exception {
		assertThat(page(get("/login"))).contains("로그인", "<html lang=\"ko\"");
		assertThat(page(get("/login").header("Accept-Language", "en-US,en;q=0.9"))).contains("Sign in", "Continue with Kakao",
				"<html lang=\"en\"").doesNotContain("로그인");
		assertThat(page(get("/login").header("Accept-Language", "ja,en;q=0.5"))).contains("ログイン", "Kakaoで続ける",
				"<html lang=\"ja\"");
		assertThat(page(get("/login").header("Accept-Language", "fr-FR"))).as("not one of the three").contains("Sign in");
	}

	@Test
	void aPickedLanguageIsRememberedInACookieAndBeatsTheBrowser() throws Exception {
		MockHttpServletResponse r = mvc.perform(get("/login?lang=ja").header("Accept-Language", "en")).andReturn().getResponse();
		assertThat(r.getContentAsString(StandardCharsets.UTF_8)).contains("ログイン");
		assertThat(r.getHeader("Set-Cookie")).contains("lang=ja", "Path=/", "HttpOnly", "SameSite=Lax");
		assertThat(page(get("/login").cookie(new Cookie("lang", "ja")).header("Accept-Language", "en"))).contains("ログイン");
		assertThat(page(get("/login").cookie(new Cookie("lang", "xx")).header("Accept-Language", "en"))).as("junk cookie")
				.contains("Sign in");
		assertThat(String.valueOf(mvc.perform(get("/login?lang=xx")).andReturn().getResponse().getHeaders("Set-Cookie"))).as("junk ?lang")
				.doesNotContain("lang=");
	}

	@Test
	void theSwitchKeepsThePagesOwnQueryButNeverAForm() throws Exception {
		String reset = page(get("/password/reset/confirm?token=abc&lang=en"));
		assertThat(reset).contains("href=\"/password/reset/confirm?token=abc&amp;lang=ja\"", "lang=ko", "lang=en");
		String posted = page(post("/signup").with(csrf()).param("email", "bad").param("password", "secret-pw-1").param("displayName", "N")
				.header("Accept-Language", "en"));
		assertThat(posted).contains("Enter a valid email address.", "href=\"/signup?lang=ja\"").doesNotContain("secret-pw-1");
	}

	@Test
	void afterAFailedPostTheSwitchGoesToTheGetRoute() throws Exception {
		assertThat(page(post("/password/reset/confirm").with(csrf()).param("token", "bad tok").param("password", "short")
				.header("Accept-Language", "en"))).contains("href=\"/password/reset/confirm?token=bad+tok&amp;lang=ja\"");
	}

	@Test
	void aRawUtf8FormIsNotDecodedBeforeTheEncodingFilter() throws Exception {
		String page = page(post("/signup").with(csrf()).contentType("application/x-www-form-urlencoded")
				.content("email=bad&password=pw-123456&displayName=%ED%99%8D%EA%B8%B8%EB%8F%99"));
		assertThat(page).contains("value=\"홍길동\"");
	}

	@Test
	void errorsAndPrivacyFollowTheLanguage() throws Exception {
		assertThat(page(post("/signup").with(csrf()).param("email", "bad").param("password", "secret-pw-1").param("displayName", "N")
				.cookie(new Cookie("lang", "ja")))).contains("正しいメールアドレスを入力してください。");
		assertThat(page(get("/privacy").cookie(new Cookie("lang", "en")))).contains("Privacy Policy", "AI-translated");
		assertThat(page(get("/privacy").cookie(new Cookie("lang", "ja")))).contains("プライバシーポリシー", "AIで翻訳");
		assertThat(page(get("/privacy").cookie(new Cookie("lang", "ko")))).contains("개인정보처리방침", "lang");
	}
}
