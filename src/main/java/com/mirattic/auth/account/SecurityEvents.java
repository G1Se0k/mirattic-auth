package com.mirattic.auth.account;

import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.util.List;
import java.util.Locale;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.stereotype.Component;

/** The account's security log (V5 `security_events`): written as things happen, read on the account page. */
@Component
public class SecurityEvents {

	public enum Type {
		SIGN_IN("로그인"),
		SIGN_IN_FAILED("잘못된 비밀번호로 로그인 시도"),
		PASSWORD_CHANGED("비밀번호 변경"),
		PASSWORD_RESET("비밀번호 재설정"),
		LINKED("로그인 방법 연결"),
		UNLINKED("로그인 방법 해제"),
		DEVICE_SIGNED_OUT("기기 로그아웃"),
		TOKEN_REUSE("이미 쓴 로그인 토큰이 다시 쓰여 그 앱 로그인을 끊음 (도용 의심)"),
		SUSPENDED("관리자가 이용 정지"),
		RESUMED("관리자가 이용 정지 해제"),
		ADMIN_SIGNED_OUT("관리자가 모든 기기에서 로그아웃");

		private final String label;

		Type(String label) {
			this.label = label;
		}

		public String label() {
			return label;
		}
	}

	public record Event(Type type, String detail, ZonedDateTime at) {
	}

	private static final ZoneId SEOUL = ZoneId.of("Asia/Seoul");

	private final JdbcTemplate jdbc;

	SecurityEvents(JdbcTemplate jdbc) {
		this.jdbc = jdbc;
	}

	/** `detail`: shown as is next to the label; never a token, password or IP. */
	public void record(String userId, Type type, String detail) {
		jdbc.update("INSERT INTO security_events (user_id, type, detail, created_at) VALUES (?, ?, ?, NOW(6))", userId,
				type.name(), detail == null || detail.length() <= 128 ? detail : detail.substring(0, 128));
	}

	/** Newest first. */
	public List<Event> recent(String userId) {
		return recent(userId, 10);
	}

	public List<Event> recent(String userId, int limit) {
		return jdbc.query("SELECT type, detail, created_at FROM security_events WHERE user_id = ? "
				+ "ORDER BY created_at DESC, id DESC LIMIT ?", (rs, n) -> new Event(Type.valueOf(rs.getString(1)),
				rs.getString(2), rs.getTimestamp(3).toInstant().atZone(SEOUL)), userId, limit);
	}

	/**
	 * Password sign-in failures of an existing email+password account are recorded for its owner (then `next`).
	 * Unknown emails and disabled accounts are not (nothing to show, nobody to show it to).
	 */
	public AuthenticationFailureHandler failedPasswords(AuthenticationFailureHandler next) {
		return (request, response, e) -> {
			String email = request.getParameter("username");
			if (e instanceof BadCredentialsException && email != null) {
				List<String> uid = jdbc.queryForList("SELECT i.user_id FROM user_identities i JOIN users u "
						+ "ON u.id = i.user_id WHERE i.provider = 'LOCAL' AND i.subject = ? AND u.status = 'ACTIVE'",
						String.class, email.trim().toLowerCase(Locale.ROOT));
				if (!uid.isEmpty()) {
					record(uid.getFirst(), Type.SIGN_IN_FAILED, Devices.label(request));
				}
			}
			next.onAuthenticationFailure(request, response, e);
		};
	}
}
