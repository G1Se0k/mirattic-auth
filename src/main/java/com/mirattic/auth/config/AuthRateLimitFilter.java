package com.mirattic.auth.config;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.HexFormat;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import org.springframework.web.util.UrlPathHelper;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * Fixed one-minute window per client IP on password-handling POSTs (brute force, signup spam, reset
 * mail spam). Runs before Spring Security, which handles POST /login itself. The token endpoint is
 * excluded: all of a product's users refresh through that product's one server IP.
 *
 * The path is matched decoded and without `;` params, the way Spring resolves it (so `/lo%67in` counts
 * as `/login`). IPv6 clients are keyed by /64, since one host can rotate through a whole /64.
 * ponytail: in-memory, capped at MAX_KEYS (new IPs are refused while full); Redis for >1 instance.
 */
@Component
@Order(Ordered.HIGHEST_PRECEDENCE)
class AuthRateLimitFilter extends OncePerRequestFilter {

	static final int MAX_KEYS = 100_000;
	private static final Set<String> LIMITED = Set.of("/login", "/signup", "/password/reset",
			"/password/reset/confirm", "/account/password");
	private static final UrlPathHelper PATHS = new UrlPathHelper();

	private record Window(long minute, int count) {
	}

	private final Map<String, Window> windows = new ConcurrentHashMap<>();
	private final int limitPerMinute;

	AuthRateLimitFilter(@Value("${auth.rate-limit-per-minute:20}") int limitPerMinute) {
		this.limitPerMinute = limitPerMinute;
	}

	@Override
	protected boolean shouldNotFilter(HttpServletRequest request) {
		return !"POST".equals(request.getMethod()) || !LIMITED.contains(PATHS.getLookupPathForRequest(request));
	}

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
			throws ServletException, IOException {
		long minute = System.currentTimeMillis() / 60_000;
		String key = clientKey(request.getRemoteAddr());
		boolean full = windows.size() >= MAX_KEYS && !windows.containsKey(key);
		Window w = full ? null : windows.merge(key, new Window(minute, 1),
				(old, one) -> old.minute() == minute ? new Window(minute, old.count() + 1) : one);
		if (w == null || w.count() > limitPerMinute) {
			response.setStatus(429);
			response.setHeader("Retry-After", "60");
			response.setContentType("text/plain;charset=UTF-8");
			response.getWriter().write("요청이 너무 많습니다. 1분 후 다시 시도하세요.");
			return;
		}
		chain.doFilter(request, response);
	}

	/** Drops finished windows off the request path. */
	@Scheduled(fixedRate = 60_000)
	void evictOldWindows() {
		long minute = System.currentTimeMillis() / 60_000;
		windows.values().removeIf(w -> w.minute() < minute);
	}

	static String clientKey(String address) {
		if (address == null || !address.contains(":")) {
			return address;
		}
		try {
			byte[] ip = InetAddress.getByName(address).getAddress();
			return ip.length == 16 ? HexFormat.of().formatHex(ip, 0, 8) + "::/64" : address;
		} catch (UnknownHostException e) {
			return address;
		}
	}
}
