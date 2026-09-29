package com.mirattic.auth.config;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.List;
import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * A browser session (password or Kakao / Naver sign-in) of an account that is no longer ACTIVE — being deleted,
 * deleted, disabled — is signed out on its next request. A sign-in that finished just as the account was fenced
 * (AccountDeletion) can leave such a session behind; it can't mint tokens (ACTIVE only), and with this it can't use
 * the account pages or SSO either. Client and bearer-token requests are not browser sessions and are left alone.
 */
final class ActiveAccountFilter extends OncePerRequestFilter {

	private final JdbcOperations jdbc;
	private final SecurityContextLogoutHandler logout = new SecurityContextLogoutHandler();

	ActiveAccountFilter(JdbcOperations jdbc) {
		this.jdbc = jdbc;
		// Only the sign-in goes; the session stays, so a pending Kakao / Naver link in it fails as a link instead of
		// its callback becoming a fresh sign-up.
		logout.setInvalidateHttpSession(false);
	}

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
			throws ServletException, IOException {
		Authentication auth = SecurityContextHolder.getContext().getAuthentication();
		if (auth instanceof UsernamePasswordAuthenticationToken || auth instanceof OAuth2AuthenticationToken) {
			List<String> status = jdbc.queryForList("SELECT status FROM users WHERE id = ?", String.class, auth.getName());
			if (!status.equals(List.of("ACTIVE"))) {
				logout.logout(request, response, auth);
			}
		}
		chain.doFilter(request, response);
	}
}
