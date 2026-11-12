package com.mirattic.auth.i18n;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.time.Duration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

/** `?lang=ko|en|ja` is remembered in a cookie (the choice, nothing else). */
@Component
@Order(Ordered.HIGHEST_PRECEDENCE)
class LangFilter extends OncePerRequestFilter {

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
			throws ServletException, IOException {
		String code = Lang.valid(Lang.queryLang(request));
		if (code != null) {
			response.addHeader(HttpHeaders.SET_COOKIE, ResponseCookie.from(Lang.COOKIE, code).path("/")
					.maxAge(Duration.ofDays(365)).sameSite("Lax").httpOnly(true).secure(request.isSecure()).build()
					.toString());
		}
		chain.doFilter(request, response);
	}
}
