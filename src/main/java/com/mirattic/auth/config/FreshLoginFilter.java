package com.mirattic.auth.config;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.FactorGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * OIDC `prompt=login` on /oauth2/authorize: a sign-in (password or Kakao / Naver) older than {@link #FRESH} is
 * ended, so the request goes through the login page again (and is replayed from there, then fresh). Used before destructive actions,
 * e.g. Sync account deletion; the client still checks the ID token's `auth_time` itself.
 */
final class FreshLoginFilter extends OncePerRequestFilter {

	static final Duration FRESH = Duration.ofSeconds(60);

	private final Clock clock;
	private final SecurityContextLogoutHandler logout = new SecurityContextLogoutHandler();

	FreshLoginFilter(Clock clock) {
		this.clock = clock;
	}

	@Override
	protected boolean shouldNotFilter(HttpServletRequest request) {
		return !"/oauth2/authorize".equals(request.getServletPath()) || !"login".equals(request.getParameter("prompt"));
	}

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
			throws ServletException, IOException {
		Authentication auth = SecurityContextHolder.getContext().getAuthentication();
		if (auth != null && !(auth instanceof AnonymousAuthenticationToken)) {
			// Latest factor (password, or Kakao / Naver sign-in), as SAS computes the ID token's auth_time.
			Instant signedIn = auth.getAuthorities().stream()
					.filter(a -> a instanceof FactorGrantedAuthority)
					.map(a -> ((FactorGrantedAuthority) a).getIssuedAt())
					.max(Instant::compareTo).orElse(Instant.EPOCH);
			if (signedIn.isBefore(clock.instant().minus(FRESH))) {
				logout.logout(request, response, auth);
			}
		}
		chain.doFilter(request, response);
	}
}
