package com.mirattic.auth.account;

import jakarta.servlet.http.HttpSession;
import java.io.Serializable;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.springframework.dao.DuplicateKeyException;
import org.springframework.dao.PessimisticLockingFailureException;
import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.FactorGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.stereotype.Component;
import org.springframework.transaction.support.TransactionTemplate;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

/**
 * Kakao / Naver sign-in. The provider's stable user id is the identity (provider, subject); the first sign-in
 * creates a new Mirattic account. Never matched to an existing account by email (docs/security.md, linking).
 * The resulting principal's name is the Mirattic UID, so tokens carry it as `sub` like a password login.
 * Link mode (a signed-in user asked for it on the account page, {@link #LINK}): the identity is added to that
 * account instead, unless it belongs to another account or the account already has this provider.
 */
@Component
public class SocialLogin implements OAuth2UserService<OAuth2UserRequest, OAuth2User> {

	/** What Auth keeps from the provider's profile. `email` and `name` may be missing (optional consent). */
	record Profile(String provider, String subject, String email, String name) {
	}

	/** Session attribute: the signed-in user asked to add this provider (AccountController). */
	public static final String LINK = SocialLogin.class.getName() + ".link";
	static final Duration LINK_TTL = Duration.ofMinutes(10);

	/** `provider`: the registration id, kakao | naver. */
	public record Link(String uid, String provider, Instant at) implements Serializable {
	}

	private final OAuth2UserService<OAuth2UserRequest, OAuth2User> fetch = new DefaultOAuth2UserService();
	private final JdbcOperations jdbc;
	private final TransactionTemplate tx;
	private final SecurityEvents events;

	SocialLogin(JdbcOperations jdbc, TransactionTemplate tx, SecurityEvents events) {
		this.jdbc = jdbc;
		this.tx = tx;
		this.events = events;
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
		Link link = takeLink(request.getClientRegistration().getRegistrationId());
		String uid;
		if (link != null) {
			try {
				tx.executeWithoutResult(s -> attach(link.uid(), p));
			} catch (DuplicateKeyException e) {
				throw failure("link_taken"); // signed in (so created) concurrently
			}
			uid = link.uid();
		} else {
			try {
				uid = tx.execute(s -> findOrCreate(p));
			} catch (DuplicateKeyException | PessimisticLockingFailureException e) {
				// A concurrent first sign-in of the same provider account won (MySQL reports a duplicate key or a
				// deadlock). Ours rolled back; this time the identity is there.
				uid = tx.execute(s -> findOrCreate(p));
			}
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

	/**
	 * The pending link of this browser, consumed. It must be for this provider, recent, and by the user still signed
	 * in here; otherwise the link fails rather than falling back to signing in as someone else.
	 */
	private static Link takeLink(String registrationId) {
		HttpSession session = RequestContextHolder.getRequestAttributes() instanceof ServletRequestAttributes a
				? a.getRequest().getSession(false) : null;
		Link link = session == null ? null : (Link) session.getAttribute(LINK);
		if (link == null) {
			return null;
		}
		session.removeAttribute(LINK);
		Authentication current = SecurityContextHolder.getContext().getAuthentication();
		if (!link.provider().equals(registrationId) || link.at().isBefore(Instant.now().minus(LINK_TTL))
				|| current == null || !link.uid().equals(current.getName())) {
			throw failure("link_failed");
		}
		return link;
	}

	/** The users row is locked first, as AccountService.unlink does. */
	private void attach(String uid, Profile p) {
		jdbc.queryForObject("SELECT id FROM users WHERE id = ? FOR UPDATE", String.class, uid);
		List<String> owner = jdbc.queryForList(
				"SELECT user_id FROM user_identities WHERE provider = ? AND subject = ? FOR UPDATE", String.class,
				p.provider(), p.subject());
		if (!owner.isEmpty()) {
			if (owner.getFirst().equals(uid)) {
				return;
			}
			throw failure("link_taken");
		}
		if (jdbc.queryForObject("SELECT COUNT(*) FROM user_identities WHERE user_id = ? AND provider = ?",
				Integer.class, uid, p.provider()) > 0) {
			throw failure("link_exists");
		}
		jdbc.update("INSERT INTO user_identities "
				+ "(id, user_id, provider, subject, email, password_hash, created_at, updated_at) "
				+ "VALUES (UUID(), ?, ?, ?, ?, NULL, NOW(6), NOW(6))", uid, p.provider(), p.subject(), p.email());
		events.record(uid, SecurityEvents.Type.LINKED, "KAKAO".equals(p.provider()) ? "카카오" : "네이버");
	}

	/**
	 * A failed link goes back to the account page (the user is still signed in there); a failed sign-in to the
	 * login page. A provider error (e.g. cancelled at Kakao) during a link leaves the pending link, cleared here.
	 */
	public static AuthenticationFailureHandler failureHandler() {
		return (request, response, e) -> {
			HttpSession session = request.getSession(false);
			boolean pending = session != null && session.getAttribute(LINK) != null;
			String code = e instanceof OAuth2AuthenticationException o ? o.getError().getErrorCode() : "";
			if (pending) {
				session.removeAttribute(LINK);
			}
			String to = code.startsWith("link_") ? "/account?link_error=" + code.substring(5)
					: pending ? "/account?link_error=failed" : "/login?social_error";
			response.sendRedirect(request.getContextPath() + to);
		};
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

	/** `link_*` codes are link failures (see failureHandler); anything else a failed sign-in. */
	private static OAuth2AuthenticationException failure(String code) {
		return new OAuth2AuthenticationException(new OAuth2Error(code.startsWith("link_") ? code : "social_login_failed",
				code, null));
	}
}
