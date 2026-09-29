package com.mirattic.auth.account;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.springframework.dao.DuplicateKeyException;
import org.springframework.dao.PessimisticLockingFailureException;
import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.security.core.authority.FactorGrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Component;
import org.springframework.transaction.support.TransactionTemplate;

/**
 * Kakao / Naver sign-in. The provider's stable user id is the identity (provider, subject); the first sign-in
 * creates a new Mirattic account. Never matched to an existing account by email (docs/security.md, linking).
 * The resulting principal's name is the Mirattic UID, so tokens carry it as `sub` like a password login.
 */
@Component
public class SocialLogin implements OAuth2UserService<OAuth2UserRequest, OAuth2User> {

	/** What Auth keeps from the provider's profile. `email` and `name` may be missing (optional consent). */
	record Profile(String provider, String subject, String email, String name) {
	}

	private final OAuth2UserService<OAuth2UserRequest, OAuth2User> fetch = new DefaultOAuth2UserService();
	private final JdbcOperations jdbc;
	private final TransactionTemplate tx;

	SocialLogin(JdbcOperations jdbc, TransactionTemplate tx) {
		this.jdbc = jdbc;
		this.tx = tx;
	}

	@Override
	public OAuth2User loadUser(OAuth2UserRequest request) {
		Map<String, Object> attributes = fetch.loadUser(request).getAttributes();
		Profile p = switch (request.getClientRegistration().getRegistrationId()) {
			case "kakao" -> kakao(attributes);
			case "naver" -> naver(attributes);
			default -> throw failure("unknown provider");
		};
		if (p.subject() == null || p.subject().isBlank()) {
			throw failure("no provider user id");
		}
		String uid;
		try {
			uid = tx.execute(s -> findOrCreate(p));
		} catch (DuplicateKeyException | PessimisticLockingFailureException e) {
			// A concurrent first sign-in of the same provider account won (MySQL reports a duplicate key or a
			// deadlock). Ours rolled back; this time the identity is there.
			uid = tx.execute(s -> findOrCreate(p));
		}
		String status = jdbc.queryForObject("SELECT status FROM users WHERE id = ?", String.class, uid);
		if (!"ACTIVE".equals(status)) {
			throw failure("account not active");
		}
		// The factor's time becomes the ID token's auth_time (and FreshLoginFilter's sign-in time).
		return new DefaultOAuth2User(List.of(new SimpleGrantedAuthority("ROLE_USER"),
				FactorGrantedAuthority.withAuthority(FactorGrantedAuthority.AUTHORIZATION_CODE_AUTHORITY)
						.issuedAt(Instant.now()).build()),
				Map.of("uid", uid), "uid");
	}

	private String findOrCreate(Profile p) {
		List<String> found = jdbc.queryForList(
				"SELECT user_id FROM user_identities WHERE provider = ? AND subject = ? FOR UPDATE", String.class,
				p.provider(), p.subject());
		if (!found.isEmpty()) {
			// Contact email only (the provider may have changed it); never used to find accounts.
			jdbc.update("UPDATE user_identities SET email = ?, updated_at = NOW(6) WHERE provider = ? AND subject = ?",
					p.email(), p.provider(), p.subject());
			return found.getFirst();
		}
		String uid = UUID.randomUUID().toString();
		jdbc.update("INSERT INTO users (id, display_name, status, created_at, updated_at) "
				+ "VALUES (?, ?, 'ACTIVE', NOW(6), NOW(6))", uid, displayName(p));
		jdbc.update("INSERT INTO user_identities "
				+ "(id, user_id, provider, subject, email, password_hash, created_at, updated_at) "
				+ "VALUES (UUID(), ?, ?, ?, ?, NULL, NOW(6), NOW(6))", uid, p.provider(), p.subject(), p.email());
		return uid;
	}

	@SuppressWarnings("unchecked")
	static Profile kakao(Map<String, Object> a) {
		Map<String, Object> account = a.get("kakao_account") instanceof Map<?, ?> m ? (Map<String, Object>) m : Map.of();
		Map<String, Object> profile = account.get("profile") instanceof Map<?, ?> m ? (Map<String, Object>) m : Map.of();
		return new Profile("KAKAO", a.get("id") == null ? null : String.valueOf(a.get("id")), str(account.get("email")), str(profile.get("nickname")));
	}

	@SuppressWarnings("unchecked")
	static Profile naver(Map<String, Object> a) {
		Map<String, Object> r = a.get("response") instanceof Map<?, ?> m ? (Map<String, Object>) m : Map.of();
		String name = str(r.get("nickname")) != null ? str(r.get("nickname")) : str(r.get("name"));
		return new Profile("NAVER", str(r.get("id")), str(r.get("email")), name);
	}

	private static String displayName(Profile p) {
		String n = p.name() == null ? "" : p.name().strip();
		if (n.isEmpty()) {
			return "KAKAO".equals(p.provider()) ? "카카오 사용자" : "네이버 사용자";
		}
		return n.length() > 64 ? n.substring(0, 64) : n;
	}

	private static String str(Object o) {
		return o instanceof String s && !s.isBlank() ? s : null;
	}

	private static OAuth2AuthenticationException failure(String message) {
		return new OAuth2AuthenticationException(new OAuth2Error("social_login_failed", message, null));
	}
}
