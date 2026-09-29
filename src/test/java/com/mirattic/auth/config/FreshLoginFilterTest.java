package com.mirattic.auth.config;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
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
	private static final String A = "response_type=code&state=a&prompt=login";
	private static final String B = "response_type=code&state=b&prompt=login";
	private final FreshLoginFilter filter = new FreshLoginFilter(Clock.fixed(NOW, ZoneOffset.UTC));

	@AfterEach
	void clear() {
		SecurityContextHolder.clearContext();
	}

	@Test
	void promptLoginEndsEvenAJustStartedSignInAndRemembersThisDemand() throws Exception {
		MockHttpSession session = signedIn(NOW);
		MockHttpServletRequest request = authorize(session, A);
		filter.doFilter(request, new MockHttpServletResponse(), new MockFilterChain());
		assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
		assertThat(session.isInvalid()).isTrue();
		assertThat(request.getSession(false).getAttribute(FreshLoginFilter.REAUTH_PENDING))
				.isEqualTo(new FreshLoginFilter.Pending(FreshLoginFilter.canonical(request), NOW));
	}

	@Test
	void theReplayOfThatDemandAfterANewSignInPassesOnceOnly() throws Exception {
		MockHttpSession session = signedIn(NOW.plusSeconds(10));
		session.setAttribute(FreshLoginFilter.REAUTH_PENDING, new FreshLoginFilter.Pending(FreshLoginFilter.canonical(authorize(new MockHttpSession(), A)), NOW));
		filter.doFilter(authorize(session, A), new MockHttpServletResponse(), new MockFilterChain());
		assertThat(session.isInvalid()).isFalse();
		assertThat(session.getAttribute(FreshLoginFilter.REAUTH_PENDING)).isNull();

		// The same request again later is a new demand: signed out again.
		filter.doFilter(authorize(session, A), new MockHttpServletResponse(), new MockFilterChain());
		assertThat(session.isInvalid()).isTrue();
	}

	@Test
	void anAbandonedDemandDoesNotLetAnotherRequestThrough() throws Exception {
		// Demand A was abandoned; the user signed in some other way afterwards; now demand B arrives.
		MockHttpSession session = signedIn(NOW.plusSeconds(10));
		session.setAttribute(FreshLoginFilter.REAUTH_PENDING, new FreshLoginFilter.Pending(FreshLoginFilter.canonical(authorize(new MockHttpSession(), A)), NOW));
		filter.doFilter(authorize(session, B), new MockHttpServletResponse(), new MockFilterChain());
		assertThat(session.isInvalid()).isTrue();
	}

	@Test
	void aSignInFromBeforeTheDemandDoesNotSatisfyIt() throws Exception {
		MockHttpSession session = signedIn(NOW.minusSeconds(1));
		session.setAttribute(FreshLoginFilter.REAUTH_PENDING, new FreshLoginFilter.Pending(FreshLoginFilter.canonical(authorize(new MockHttpSession(), A)), NOW));
		filter.doFilter(authorize(session, A), new MockHttpServletResponse(), new MockFilterChain());
		assertThat(session.isInvalid()).isTrue();
	}

	@Test
	void promptIsASpaceSeparatedList() {
		assertThat(FreshLoginFilter.asksForLogin("login")).isTrue();
		assertThat(FreshLoginFilter.asksForLogin("consent login")).isTrue();
		assertThat(FreshLoginFilter.asksForLogin(" login  consent ")).isTrue();
		assertThat(FreshLoginFilter.asksForLogin("consent")).isFalse();
		assertThat(FreshLoginFilter.asksForLogin("loginx")).isFalse();
		assertThat(FreshLoginFilter.asksForLogin(null)).isFalse();
	}

	@Test
	void noPromptLeavesTheSessionAlone() throws Exception {
		MockHttpSession session = signedIn(NOW.minusSeconds(3600));
		filter.doFilter(authorize(session, "response_type=code&state=c"), new MockHttpServletResponse(), new MockFilterChain());
		assertThat(session.isInvalid()).isFalse();
		assertThat(SecurityContextHolder.getContext().getAuthentication()).isNotNull();
	}

	private static MockHttpSession signedIn(Instant at) {
		SecurityContextHolder.getContext().setAuthentication(new TestingAuthenticationToken("uid", null,
				List.of(FactorGrantedAuthority.withAuthority(FactorGrantedAuthority.PASSWORD_AUTHORITY).issuedAt(at).build())));
		return new MockHttpSession();
	}

	private static MockHttpServletRequest authorize(MockHttpSession session, String query) {
		MockHttpServletRequest req = new MockHttpServletRequest("GET", "/oauth2/authorize");
		req.setQueryString(query);
		for (String pair : query.split("&")) {
			String[] kv = pair.split("=", 2);
			req.addParameter(kv[0], kv[1]);
		}
		req.setSession(session);
		return req;
	}
}
