package com.mirattic.auth.config;

import com.mirattic.auth.account.Devices;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Duration;
import java.util.Base64;
import java.util.HexFormat;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * A random, long-lived id for the browser that starts an app login (/oauth2/authorize), so the account page can
 * tell the same product signed in again from the same browser (one device) from another computer. The
 * authorization saved during that request is tagged with it (HashedTokenAuthorizationService). Not a credential:
 * it only groups rows in the owner's own list.
 */
class DeviceCookie extends OncePerRequestFilter {

	static final String NAME = "MIRATTIC_DEVICE";
	/** Request attribute: the {@link Device} of this /oauth2/authorize request. */
	static final String ATTRIBUTE = DeviceCookie.class.getName();
	private static final String PATH = "/oauth2/authorize";
	private static final SecureRandom RANDOM = new SecureRandom();

	record Device(String id, String label) {
	}

	@Override
	protected boolean shouldNotFilter(HttpServletRequest request) {
		return !PATH.equals(request.getRequestURI());
	}

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
			throws ServletException, IOException {
		String value = read(request);
		if (value == null) {
			byte[] bytes = new byte[32];
			RANDOM.nextBytes(bytes);
			value = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
		}
		// Sent again every time, so a browser that keeps using the product keeps its id.
		response.addHeader(HttpHeaders.SET_COOKIE, ResponseCookie.from(NAME, value).path(PATH).maxAge(Duration.ofDays(400))
				.httpOnly(true).secure(request.isSecure()).sameSite("Lax").build().toString());
		request.setAttribute(ATTRIBUTE, new Device(sha256(value), Devices.label(request)));
		chain.doFilter(request, response);
	}

	private static String read(HttpServletRequest request) {
		if (request.getCookies() != null) {
			for (Cookie c : request.getCookies()) {
				if (NAME.equals(c.getName()) && c.getValue().matches("[A-Za-z0-9_-]{43}")) {
					return c.getValue();
				}
			}
		}
		return null;
	}

	private static String sha256(String value) {
		try {
			return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8)));
		} catch (NoSuchAlgorithmException e) {
			throw new IllegalStateException(e);
		}
	}
}
