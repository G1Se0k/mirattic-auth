package com.mirattic.auth.account;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;
import java.util.Locale;
import java.util.UUID;
import java.util.regex.Pattern;
import org.springframework.dao.DuplicateKeyException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.scheduling.annotation.Async;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/** LOCAL (email + password) accounts. All times come from the DB clock (session time zone UTC). */
@Service
public class AccountService {

	public record Account(String id, String displayName, String email) {
	}

	private static final Pattern EMAIL = Pattern.compile("^[^@\\s]+@[^@\\s]+\\.[^@\\s]+$");
	private static final SecureRandom RANDOM = new SecureRandom();

	private final JdbcTemplate jdbc;
	private final PasswordEncoder passwordEncoder;
	private final PasswordResetMailer mailer;

	AccountService(JdbcTemplate jdbc, PasswordEncoder passwordEncoder, PasswordResetMailer mailer) {
		this.jdbc = jdbc;
		this.passwordEncoder = passwordEncoder;
		this.mailer = mailer;
	}

	/** Returns the new Mirattic UID. */
	@Transactional
	public String signup(String email, String password, String displayName) {
		String normalized = normalizeEmail(email);
		if (!EMAIL.matcher(normalized).matches() || normalized.length() > 254) {
			throw new AccountException("올바른 이메일을 입력하세요.");
		}
		String name = validDisplayName(displayName);
		checkPassword(password);
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

	/**
	 * Async as a whole (lookup, token, mail), so the caller's response is identical in content and
	 * timing whether or not the email exists.
	 */
	@Async
	@Transactional
	public void requestPasswordReset(String email) {
		String normalized = normalizeEmail(email);
		// The row lock serializes concurrent requests for one account, so the throttle below holds:
		// at most one mail per account per minute, whatever the number of requesting IPs.
		List<String> ids = jdbc.queryForList("""
				SELECT u.id FROM user_identities i JOIN users u ON u.id = i.user_id
				WHERE i.provider = 'LOCAL' AND i.subject = ? AND u.status = 'ACTIVE' FOR UPDATE
				""", String.class, normalized);
		if (ids.isEmpty() || jdbc.queryForObject("SELECT COUNT(*) FROM password_reset_tokens "
				+ "WHERE user_id = ? AND created_at > NOW(6) - INTERVAL 1 MINUTE", Integer.class, ids.getFirst()) > 0) {
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
		setPassword(ids.getFirst(), newPassword);
	}

	@Transactional
	public void changePassword(String userId, String currentPassword, String newPassword) {
		List<String> hashes = jdbc.queryForList(
				"SELECT password_hash FROM user_identities WHERE user_id = ? AND provider = 'LOCAL'",
				String.class, userId);
		if (hashes.isEmpty() || !passwordEncoder.matches(currentPassword, hashes.getFirst())) {
			throw new AccountException("현재 비밀번호가 올바르지 않습니다.");
		}
		checkPassword(newPassword);
		setPassword(userId, newPassword);
	}

	public void changeDisplayName(String userId, String displayName) {
		jdbc.update("UPDATE users SET display_name = ?, updated_at = NOW(6) WHERE id = ?",
				validDisplayName(displayName), userId);
	}

	public Account find(String userId) {
		return jdbc.queryForObject("""
				SELECT u.id, u.display_name, i.email FROM users u
				LEFT JOIN user_identities i ON i.user_id = u.id AND i.provider = 'LOCAL'
				WHERE u.id = ?
				""", (rs, n) -> new Account(rs.getString(1), rs.getString(2), rs.getString(3)), userId);
	}

	/** A new password also kills every outstanding reset link and OAuth authorization (refresh tokens). */
	private void setPassword(String userId, String password) {
		jdbc.update("UPDATE user_identities SET password_hash = ?, updated_at = NOW(6) "
				+ "WHERE user_id = ? AND provider = 'LOCAL'", passwordEncoder.encode(password), userId);
		jdbc.update("UPDATE password_reset_tokens SET used_at = NOW(6) WHERE user_id = ? AND used_at IS NULL",
				userId);
		jdbc.update("DELETE FROM oauth2_authorization WHERE principal_name = ?", userId);
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

	static String sha256(String value) {
		try {
			return HexFormat.of().formatHex(
					MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8)));
		} catch (NoSuchAlgorithmException e) {
			throw new IllegalStateException(e);
		}
	}
}
