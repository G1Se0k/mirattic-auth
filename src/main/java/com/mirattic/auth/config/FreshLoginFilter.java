package com.mirattic.auth.config;

import com.mirattic.auth.account.AccountService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import java.io.IOException;
import java.io.Serializable;
import java.time.Clock;
import java.time.Instant;
import java.util.Arrays;
import java.util.TreeMap;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * OIDC `prompt=login` on /oauth2/authorize: the user must sign in again (password or Kakao / Naver), however
 * recent the current Auth session is. The existing sign-in is ended and the request goes through the login page.
 * Only the replay of <em>that</em> request (same parameters: state, PKCE challenge, ...) after a sign-in newer
 * than the demand passes, once — so an abandoned demand can't be satisfied later by an ordinary sign-in.
 * Used before destructive actions (Sync account deletion, Flow withdrawal) and after a product logout.
 * Clients still check the ID token's `auth_time` themselves.
 */
final class FreshLoginFilter extends OncePerRequestFilter {

	/** The pending demand: which request, since when. Survives the sign-in (session attributes are migrated). */
	static final String REAUTH_PENDING = FreshLoginFilter.class.getName() + ".pending";

	record Pending(String query, Instant demandedAt) implements Serializable {
	}

	private final SecurityContextLogoutHandler logout = new SecurityContextLogoutHandler();
	private final Clock clock;

	FreshLoginFilter(Clock clock) {
		this.clock = clock;
	}

	@Override
	protected boolean shouldNotFilter(HttpServletRequest request) {
		return !(request.getContextPath() + "/oauth2/authorize").equals(request.getRequestURI())
				|| !asksForLogin(request.getParameter("prompt"));
	}

	/** OIDC `prompt` is a space-separated list ("login consent" asks for a login too). */
	static boolean asksForLogin(String prompt) {
		return prompt != null && Arrays.asList(prompt.trim().split("\\s+")).contains("login");
	}

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
			throws ServletException, IOException {
		Authentication auth = SecurityContextHolder.getContext().getAuthentication();
		boolean signedIn = auth != null && !(auth instanceof AnonymousAuthenticationToken);
		HttpSession session = request.getSession(false);
		Pending pending = session == null ? null : (Pending) session.getAttribute(REAUTH_PENDING);
		String query = canonical(request);
		if (signedIn && pending != null && pending.query().equals(query)
				&& !AccountService.signInTime(auth).isBefore(pending.demandedAt())) {
			// The replay of this very demand, after a new sign-in: let it through once.
			session.removeAttribute(REAUTH_PENDING);
		} else {
			if (signedIn) {
				logout.logout(request, response, auth);
			}
			request.getSession(true).setAttribute(REAUTH_PENDING, new Pending(query, clock.instant()));
		}
		chain.doFilter(request, response);
	}

	/**
	 * The request's parameters, decoded and sorted: the replay after sign-in re-encodes the query string, and Spring
	 * Security's saved-request redirect adds a `continue` parameter.
	 */
	static String canonical(HttpServletRequest request) {
		StringBuilder out = new StringBuilder();
		new TreeMap<>(request.getParameterMap()).forEach((name, values) -> {
			if (!"continue".equals(name)) {
				out.append(name).append('=').append(String.join(",", values)).append('&');
			}
		});
		return out.toString();
	}
}
