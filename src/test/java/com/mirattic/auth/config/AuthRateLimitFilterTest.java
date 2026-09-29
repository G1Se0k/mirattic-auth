package com.mirattic.auth.config;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

class AuthRateLimitFilterTest {

	final AuthRateLimitFilter filter = new AuthRateLimitFilter(2);

	int post(String uri, String ip) throws Exception {
		MockHttpServletRequest request = new MockHttpServletRequest("POST", uri);
		request.setRemoteAddr(ip);
		MockHttpServletResponse response = new MockHttpServletResponse();
		filter.doFilter(request, response, new MockFilterChain());
		return response.getStatus();
	}

	@Test
	void limitsPasswordPostsPerIp() throws Exception {
		assertThat(post("/login", "1.1.1.1")).isEqualTo(200);
		assertThat(post("/signup", "1.1.1.1")).isEqualTo(200);
		assertThat(post("/password/reset", "1.1.1.1")).isEqualTo(429);
		assertThat(post("/login", "2.2.2.2")).as("other IP").isEqualTo(200);
		assertThat(post("/oauth2/token", "1.1.1.1")).as("token endpoint excluded").isEqualTo(200);
	}

	@Test
	void encodedAndParameterizedPathsCountAsTheRealOne() throws Exception {
		assertThat(post("/lo%67in", "3.3.3.3")).isEqualTo(200);
		assertThat(post("/login;x=1", "3.3.3.3")).isEqualTo(200);
		assertThat(post("/login", "3.3.3.3")).isEqualTo(429);
	}

	@Test
	void ipv6IsKeyedBySlash64() throws Exception {
		assertThat(post("/login", "2001:db8:1:2::a")).isEqualTo(200);
		assertThat(post("/login", "2001:db8:1:2::b")).isEqualTo(200);
		assertThat(post("/login", "2001:db8:1:2:ffff::1")).as("same /64").isEqualTo(429);
		assertThat(post("/login", "2001:db8:1:3::a")).as("other /64").isEqualTo(200);
	}
}
