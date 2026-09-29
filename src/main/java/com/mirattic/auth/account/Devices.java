package com.mirattic.auth.account;

import jakarta.servlet.http.HttpServletRequest;
import java.io.Serializable;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HexFormat;
import java.util.List;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.session.FindByIndexNameSessionRepository;
import org.springframework.session.Session;
import org.springframework.stereotype.Component;

/**
 * Where the account is signed in: Auth browser sessions (SSO) and app logins (an OAuth authorization with a live
 * refresh token: Sync, Flow). Either can be ended from the account page.
 */
@Component
public class Devices {

	/** Session attribute set at sign-in. Sessions from before it existed have none. */
	static final String SIGN_IN = Devices.class.getName() + ".signIn";

	record SignIn(String label, Instant at) implements Serializable {
	}

	/**
	 * `id`: a hash of the session id for browsers (the id itself is the cookie value, never put in a page), the
	 * authorization id for apps. `current`: this browser.
	 */
	public record Device(String id, boolean app, String label, ZonedDateTime signedInAt, ZonedDateTime lastUsedAt,
			boolean current) {
	}

	private static final ZoneId SEOUL = ZoneId.of("Asia/Seoul");

	private final FindByIndexNameSessionRepository<? extends Session> sessions;
	private final JdbcTemplate jdbc;
	private final RegisteredClientRepository clients;

	Devices(FindByIndexNameSessionRepository<? extends Session> sessions, JdbcTemplate jdbc,
			RegisteredClientRepository clients) {
		this.sessions = sessions;
		this.jdbc = jdbc;
		this.clients = clients;
	}

	/** Records the browser on the (already fixation-protected) session, then does what `next` does. */
	public static AuthenticationSuccessHandler recording(AuthenticationSuccessHandler next) {
		return (request, response, auth) -> {
			request.getSession().setAttribute(SIGN_IN, new SignIn(label(request), Instant.now()));
			next.onAuthenticationSuccess(request, response, auth);
		};
	}

	/** Newest first; this browser on top. */
	public List<Device> list(String userId, String currentSessionId) {
		List<Device> out = new ArrayList<>();
		sessions.findByPrincipalName(userId).forEach((id, s) -> {
			SignIn in = s.getAttribute(SIGN_IN);
			out.add(new Device(hash(id), false, in == null ? "알 수 없는 브라우저" : in.label(),
					in == null ? null : seoul(in.at()), seoul(s.getLastAccessedTime()), id.equals(currentSessionId)));
		});
		jdbc.query("""
				SELECT id, registered_client_id, authorization_code_issued_at, refresh_token_issued_at
				FROM oauth2_authorization
				WHERE principal_name = ? AND refresh_token_value IS NOT NULL AND refresh_token_expires_at > NOW()
				""", rs -> {
			RegisteredClient client = clients.findById(rs.getString(2));
			var started = rs.getTimestamp(3);
			out.add(new Device(rs.getString(1), true, client == null ? rs.getString(2) : client.getClientName(),
					started == null ? null : seoul(started.toInstant()), seoul(rs.getTimestamp(4).toInstant()), false));
		}, userId);
		out.sort(Comparator.comparing(Device::current).thenComparing(Device::lastUsedAt).reversed());
		return out;
	}

	/** Signs one browser or app out. Only the user's own; this browser is ended by logging out instead. */
	public void end(String userId, String deviceId, String currentSessionId) {
		if (jdbc.update("DELETE FROM oauth2_authorization WHERE id = ? AND principal_name = ?", deviceId, userId) > 0) {
			return;
		}
		sessions.findByPrincipalName(userId).keySet().stream()
				.filter(id -> hash(id).equals(deviceId) && !id.equals(currentSessionId))
				.forEach(sessions::deleteById);
	}

	private static ZonedDateTime seoul(Instant at) {
		return at.atZone(SEOUL);
	}

	static String hash(String sessionId) {
		try {
			return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
					.digest(sessionId.getBytes(StandardCharsets.UTF_8)));
		} catch (NoSuchAlgorithmException e) {
			throw new IllegalStateException(e);
		}
	}

	/** "Chrome · Windows". Order matters: Edge, Whale and Samsung say Chrome too, Chrome says Safari. */
	static String label(HttpServletRequest request) {
		String ua = String.valueOf(request.getHeader("User-Agent"));
		String browser = first(ua, "Edg/", "Edge", "Whale/", "Whale", "SamsungBrowser/", "삼성 인터넷",
				"KAKAOTALK", "카카오톡", "NAVER(", "네이버 앱", "Firefox/", "Firefox", "Chrome/", "Chrome",
				"CriOS/", "Chrome", "Safari/", "Safari");
		String os = first(ua, "iPhone", "iPhone", "iPad", "iPad", "Android", "Android", "Windows", "Windows",
				"Mac OS X", "Mac", "Linux", "Linux");
		if (browser == null && os == null) {
			return "알 수 없는 브라우저";
		}
		return browser == null ? os : os == null ? browser : browser + " · " + os;
	}

	/** Pairs of (marker, name): the name of the first marker found in `ua`. */
	private static String first(String ua, String... pairs) {
		for (int i = 0; i < pairs.length; i += 2) {
			if (ua.contains(pairs[i])) {
				return pairs[i + 1];
			}
		}
		return null;
	}
}
