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
import java.util.HashSet;
import java.util.HexFormat;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.session.FindByIndexNameSessionRepository;
import org.springframework.session.Session;
import org.springframework.stereotype.Component;

/**
 * Where the account is signed in: Auth browser sessions (SSO) and app logins (an OAuth authorization with a live
 * refresh token: Sync, Flow). Either can be ended from the account page. Logins of one product started from the same
 * browser (DeviceCookie) show as one device and end together: a product that signs in again without revoking its
 * previous login (reinstalled, storage cleared, sign-in abandoned) would otherwise list the same computer many times.
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
	private final SecurityEvents events;

	Devices(FindByIndexNameSessionRepository<? extends Session> sessions, JdbcTemplate jdbc,
			RegisteredClientRepository clients, SecurityEvents events) {
		this.sessions = sessions;
		this.jdbc = jdbc;
		this.clients = clients;
		this.events = events;
	}

	/**
	 * Records the browser on the (already fixation-protected) session and the sign-in in the security log, then
	 * does what `next` does.
	 */
	public AuthenticationSuccessHandler recording(AuthenticationSuccessHandler next) {
		return (request, response, auth) -> {
			String label = label(request);
			request.getSession().setAttribute(SIGN_IN, new SignIn(label, Instant.now()));
			String method = auth instanceof OAuth2AuthenticationToken social
					? SocialLogin.providerName(social.getAuthorizedClientRegistrationId().toUpperCase(Locale.ROOT)) : "이메일";
			events.record(auth.getName(), SecurityEvents.Type.SIGN_IN, method + " · " + label);
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
		Set<String> seen = new HashSet<>();
		// Newest first, so the one kept of a browser's logins of a product is the one in use.
		jdbc.query("""
				SELECT id, registered_client_id, authorization_code_issued_at, refresh_token_issued_at, device_id,
				       device_label
				FROM oauth2_authorization
				WHERE principal_name = ? AND refresh_token_value IS NOT NULL AND refresh_token_expires_at > NOW()
				ORDER BY refresh_token_issued_at DESC
				""", rs -> {
			String device = rs.getString(5);
			if (device != null && !seen.add(rs.getString(2) + " " + device)) {
				return;
			}
			RegisteredClient client = clients.findById(rs.getString(2));
			String name = client == null ? rs.getString(2) : client.getClientName();
			var started = rs.getTimestamp(3);
			out.add(new Device(rs.getString(1), true, rs.getString(6) == null ? name : name + " · " + rs.getString(6),
					started == null ? null : seoul(started.toInstant()), seoul(rs.getTimestamp(4).toInstant()), false));
		}, userId);
		out.sort(Comparator.comparing(Device::current).thenComparing(Device::lastUsedAt).reversed());
		return out;
	}

	/**
	 * Signs one browser or app out. Only the user's own; this browser is ended by logging out instead. An app login
	 * ends with the other logins of that product from the same browser (listed as one device).
	 */
	public void end(String userId, String deviceId, String currentSessionId) {
		List<String> app = jdbc.queryForList("SELECT registered_client_id FROM oauth2_authorization "
				+ "WHERE id = ? AND principal_name = ?", String.class, deviceId, userId);
		if (!app.isEmpty()) {
			if (jdbc.update("""
					DELETE a FROM oauth2_authorization a
					JOIN oauth2_authorization picked ON picked.id = ? AND picked.principal_name = a.principal_name
					WHERE a.principal_name = ? AND (a.id = picked.id OR (a.registered_client_id = picked.registered_client_id
					      AND a.device_id = picked.device_id))
					""", deviceId, userId) > 0) {
				RegisteredClient client = clients.findById(app.getFirst());
				events.record(userId, SecurityEvents.Type.DEVICE_SIGNED_OUT,
						client == null ? null : client.getClientName());
			}
			return;
		}
		sessions.findByPrincipalName(userId).forEach((id, s) -> {
			if (hash(id).equals(deviceId) && !id.equals(currentSessionId)) {
				SignIn in = s.getAttribute(SIGN_IN);
				sessions.deleteById(id);
				events.record(userId, SecurityEvents.Type.DEVICE_SIGNED_OUT, in == null ? null : in.label());
			}
		});
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
	public static String label(HttpServletRequest request) {
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
