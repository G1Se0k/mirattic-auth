package com.mirattic.auth.config;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.authority.FactorGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;

class FreshLoginFilterTest {

	private static final Instant NOW = Instant.parse("2026-09-29T00:00:00Z");
	private final FreshLoginFilter filter = new FreshLoginFilter(Clock.fixed(NOW, ZoneOffset.UTC));

	@AfterEach
	void clear() {
		SecurityContextHolder.clearContext();
	}

	@Test
	void promptLoginEndsAnOldPasswordSignIn() throws Exception {
		MockHttpSession session = signedIn(NOW.minusSeconds(61));
		filter.doFilter(authorize(session, "login"), new MockHttpServletResponse(), new MockFilterChain());
		assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
		assertThat(session.isInvalid()).isTrue();
	}

	@Test
	void freshSignInOrNoPromptIsKept() throws Exception {
		MockHttpSession fresh = signedIn(NOW.minusSeconds(30));
		filter.doFilter(authorize(fresh, "login"), new MockHttpServletResponse(), new MockFilterChain());
		assertThat(fresh.isInvalid()).isFalse();

		MockHttpSession old = signedIn(NOW.minusSeconds(3600));
		filter.doFilter(authorize(old, null), new MockHttpServletResponse(), new MockFilterChain());
		assertThat(old.isInvalid()).isFalse();
		assertThat(SecurityContextHolder.getContext().getAuthentication()).isNotNull();
	}

	private static MockHttpSession signedIn(Instant at) {
		SecurityContextHolder.getContext().setAuthentication(new TestingAuthenticationToken("uid", null,
				java.util.List.of(FactorGrantedAuthority.withAuthority(FactorGrantedAuthority.PASSWORD_AUTHORITY)
						.issuedAt(at).build())));
		return new MockHttpSession();
	}

	private static MockHttpServletRequest authorize(MockHttpSession session, String prompt) {
		MockHttpServletRequest req = new MockHttpServletRequest("GET", "/oauth2/authorize");
		req.setServletPath("/oauth2/authorize");
		req.setSession(session);
		if (prompt != null) {
			req.setParameter("prompt", prompt);
		}
		return req;
	}
}
