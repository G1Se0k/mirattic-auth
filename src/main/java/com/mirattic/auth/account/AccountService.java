package com.mirattic.auth.account;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;
import java.util.Locale;
import java.util.UUID;
import java.util.regex.Pattern;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import com.mirattic.auth.config.ClientIp;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.dao.DuplicateKeyException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.scheduling.annotation.Async;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.session.FindByIndexNameSessionRepository;
import org.springframework.session.Session;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/** LOCAL (email + password) accounts. All times come from the DB clock (session time zone UTC). */
@Service
public class AccountService {

	/** `email`: the LOCAL identity's, else a Kakao / Naver one's (may be null). `providers`: LOCAL, KAKAO, NAVER. */
	public record Account(String id, String displayName, String email, List<String> providers) {
		public boolean hasPassword() {
			return providers.contains("LOCAL");
		}
	}

	/** SQL: the account's contact email (LOCAL first, then the oldest identity that has one), for `u.id`. */
	public static final String CONTACT_EMAIL = "SELECT i.email FROM user_identities i WHERE i.user_id = u.id "
			+ "AND i.email IS NOT NULL ORDER BY i.provider = 'LOCAL' DESC, i.created_at LIMIT 1";

	private static final Pattern EMAIL = Pattern.compile("^[^@\\s]+@[^@\\s]+\\.[^@\\s]+$");
	private static final SecureRandom RANDOM = new SecureRandom();

	private final byte[] ipHashKey;
	private final JdbcTemplate jdbc;
	private final PasswordEncoder passwordEncoder;
	private final PasswordResetMailer mailer;
	private final FindByIndexNameSessionRepository<? extends Session> sessions;

	AccountService(JdbcTemplate jdbc, PasswordEncoder passwordEncoder, PasswordResetMailer mailer,
			FindByIndexNameSessionRepository<? extends Session> sessions,
			@Value("${auth.signup-ip-key:}") String signupIpKey) {
		if (signupIpKey.isBlank()) {
			this.ipHashKey = new byte[32];
			RANDOM.nextBytes(ipHashKey);
		} else {
			this.ipHashKey = signupIpKey.getBytes(StandardCharsets.UTF_8);
		}
		this.jdbc = jdbc;
		this.passwordEncoder = passwordEncoder;
		this.mailer = mailer;
		this.sessions = sessions;
	}

	/**
	 * Returns the new Mirattic UID. One LOCAL signup per client network (ClientIp) per 24 h; a signup
	 * that fails later (e.g. duplicate email) rolls back and does not use up the slot.
	 * Future social (Google/Apple) signups are not subject to this limit.
	 */
	@Transactional
	public String signup(String email, String password, String displayName, String clientIp) {
		String normalized = normalizeEmail(email);
		if (!EMAIL.matcher(normalized).matches() || normalized.length() > 254) {
			throw new AccountException("올바른 이메일을 입력하세요.");
		}
		String name = validDisplayName(displayName);
		checkPassword(password);
		claimSignupSlot(clientIp);
		String id = UUID.randomUUID().toString();
		jdbc.update("INSERT INTO users (id, display_name, status, created_at, updated_at) "
				+ "VALUES (?, ?, 'ACTIVE', NOW(6), NOW(6))", id, name);
		try {
			jdbc.update("INSERT INTO user_identities "
					+ "(id, user_id, provider, subject, email, password_hash, created_at, updated_at) "
					+ "VALUES (UUID(), ?, 'LOCAL', ?, ?, ?, NOW(6), NOW(6))",
					id, normalized, normalized, passwordEncoder.encode(password));
		} catch (DuplicateKeyException e) {
			// Rolls back the users row too.
			throw new AccountException("이미 가입된 이메일입니다.");
		}
		return id;
	}

	private void claimSignupSlot(String clientIp) {
		String ipHash = ipKeyHash(String.valueOf(ClientIp.key(clientIp)));
		jdbc.update("INSERT IGNORE INTO signup_ips (ip_hash, last_signup_at) VALUES (?, '1970-01-02')", ipHash);
		// Row lock: concurrent signups from one network are serialized, so only one gets through.
		boolean recent = jdbc.queryForObject("SELECT last_signup_at > NOW(6) - INTERVAL 1 DAY FROM signup_ips "
				+ "WHERE ip_hash = ? FOR UPDATE", Boolean.class, ipHash);
		if (recent) {
			throw new AccountException("이 네트워크에서는 하루에 한 계정만 만들 수 있습니다. 내일 다시 시도하세요.");
		}
		jdbc.update("UPDATE signup_ips SET last_signup_at = NOW(6) WHERE ip_hash = ?", ipHash);
	}

	/**
	 * Async as a whole (lookup, token, mail), so the caller's response is identical in content and
	 * timing whether or not the email exists.
	 */
	@Async
	@Transactional
	public void requestPasswordReset(String email) {
		String normalized = normalizeEmail(email);
		// The row lock serializes concurrent requests for one account, so the throttle below holds:
		// at most one reset mail per account per 24 h, whatever the number of requesting IPs
		// (mail-bombing guard and Resend quota). The page can't say so without revealing the account.
		List<String> ids = jdbc.queryForList("""
				SELECT u.id FROM user_identities i JOIN users u ON u.id = i.user_id
				WHERE i.provider = 'LOCAL' AND i.subject = ? AND u.status = 'ACTIVE' FOR UPDATE
				""", String.class, normalized);
		if (ids.isEmpty() || jdbc.queryForObject("SELECT COUNT(*) FROM password_reset_tokens "
				+ "WHERE user_id = ? AND created_at > NOW(6) - INTERVAL 1 DAY", Integer.class, ids.getFirst()) > 0) {
			return;
		}
		String token = newToken();
		jdbc.update("INSERT INTO password_reset_tokens (id, user_id, token_hash, expires_at, created_at) "
				+ "VALUES (UUID(), ?, ?, NOW(6) + INTERVAL 30 MINUTE, NOW(6))", ids.getFirst(), sha256(token));
		mailer.send(normalized, token);
	}

	/** One-time: the row lock + used_at makes a second (or concurrent) use fail. */
	@Transactional
	public void resetPassword(String token, String newPassword) {
		checkPassword(newPassword);
		List<String> ids = jdbc.queryForList("""
				SELECT user_id FROM password_reset_tokens
				WHERE token_hash = ? AND used_at IS NULL AND expires_at > NOW(6) FOR UPDATE
				""", String.class, sha256(token == null ? "" : token));
		if (ids.isEmpty()) {
			throw new AccountException("링크가 만료되었거나 이미 사용되었습니다. 다시 요청하세요.");
		}
		setPassword(ids.getFirst(), newPassword, null);
	}

	/** Keeps only `currentSessionId` (the browser that changed it) signed in to Auth. */
	@Transactional
	public void changePassword(String userId, String currentPassword, String newPassword, String currentSessionId) {
		List<String> hashes = jdbc.queryForList(
				"SELECT password_hash FROM user_identities WHERE user_id = ? AND provider = 'LOCAL'",
				String.class, userId);
		if (hashes.isEmpty() || !passwordEncoder.matches(currentPassword, hashes.getFirst())) {
			throw new AccountException("현재 비밀번호가 올바르지 않습니다.");
		}
		checkPassword(newPassword);
		setPassword(userId, newPassword, currentSessionId);
	}

	public void changeDisplayName(String userId, String displayName) {
		jdbc.update("UPDATE users SET display_name = ?, updated_at = NOW(6) WHERE id = ?",
				validDisplayName(displayName), userId);
	}

	public Account find(String userId) {
		return jdbc.queryForObject("""
				SELECT u.id, u.display_name, (%s),
				  (SELECT GROUP_CONCAT(i.provider ORDER BY i.created_at) FROM user_identities i WHERE i.user_id = u.id)
				FROM users u WHERE u.id = ?
				""".formatted(CONTACT_EMAIL), (rs, n) -> new Account(rs.getString(1), rs.getString(2), rs.getString(3),
				rs.getString(4) == null ? List.of() : List.of(rs.getString(4).split(","))), userId);
	}

	/**
	 * A new password also kills every outstanding reset link, OAuth authorization (refresh tokens) and
	 * Auth browser session (SSO) of the user, except `keepSessionId`.
	 */
	private void setPassword(String userId, String password, String keepSessionId) {
		jdbc.update("UPDATE user_identities SET password_hash = ?, updated_at = NOW(6) "
				+ "WHERE user_id = ? AND provider = 'LOCAL'", passwordEncoder.encode(password), userId);
		jdbc.update("UPDATE password_reset_tokens SET used_at = NOW(6) WHERE user_id = ? AND used_at IS NULL",
				userId);
		endSessions(userId, keepSessionId);
	}

	/**
	 * Signs the user out everywhere: every OAuth authorization (refresh tokens of Sync, Flow, ...; their access
	 * tokens lapse within 15 min) and every Auth browser session except `keepSessionId` (null: all).
	 */
	public void endSessions(String userId, String keepSessionId) {
		jdbc.update("DELETE FROM oauth2_authorization WHERE principal_name = ?", userId);
		sessions.findByPrincipalName(userId).keySet().stream()
				.filter(id -> !id.equals(keepSessionId))
				.forEach(sessions::deleteById);
	}

	/** The Mirattic UID behind a Kakao / Naver identity, if any. */
	public java.util.Optional<String> userOfIdentity(String provider, String subject) {
		return jdbc.queryForList("SELECT user_id FROM user_identities WHERE provider = ? AND subject = ?",
				String.class, provider, subject).stream().findFirst();
	}

	/** BCrypt only uses the first 72 bytes, so longer passwords are refused rather than silently cut. */
	private static void checkPassword(String password) {
		if (password == null || password.length() < 8 || password.getBytes(StandardCharsets.UTF_8).length > 72) {
			throw new AccountException("비밀번호는 8자 이상, 72바이트 이하여야 합니다.");
		}
	}

	private static String validDisplayName(String displayName) {
		String name = displayName == null ? "" : displayName.strip();
		if (name.isEmpty() || name.length() > 64) {
			throw new AccountException("이름은 1~64자여야 합니다.");
		}
		return name;
	}

	static String normalizeEmail(String email) {
		return email == null ? "" : email.trim().toLowerCase(Locale.ROOT);
	}

	private static String newToken() {
		byte[] bytes = new byte[32];
		RANDOM.nextBytes(bytes);
		return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
	}

	/**
	 * Keyed hash of a client network for the signup limit. A plain SHA-256 of an IPv4 address is easy to reverse
	 * (only 2^32 inputs); an HMAC with a secret key is not. The key (SIGNUP_IP_KEY) lives only in the server's
	 * environment and must survive restarts, or every deploy would reset the limit; without it (local, tests) a
	 * random one is used.
	 */
	private String ipKeyHash(String networkKey) {
		try {
			Mac mac = Mac.getInstance("HmacSHA256");
			mac.init(new SecretKeySpec(ipHashKey, "HmacSHA256"));
			return HexFormat.of().formatHex(mac.doFinal(networkKey.getBytes(StandardCharsets.UTF_8)));
		} catch (GeneralSecurityException e) {
			throw new IllegalStateException(e);
		}
	}

	static String sha256(String value) {
		try {
			return HexFormat.of().formatHex(
					MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8)));
		} catch (NoSuchAlgorithmException e) {
			throw new IllegalStateException(e);
		}
	}
}
