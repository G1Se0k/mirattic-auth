package com.mirattic.auth.account;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * Kakao "연결 끊기 알림" (unlink webhook, https://developers.kakao.com/docs/ko/kakaologin/callback): the user unlinked
 * Mirattic in Kakao, or left Kakao. That Mirattic account is signed out everywhere (KakaoUnlinkQueue). The account and
 * its Kakao identity stay: the Kakao member number is fixed per app, so signing in with Kakao again returns to the same
 * account (deleting the identity would make a new, empty account instead).
 * Authenticated by `Authorization: KakaoAK {primary Admin key}`. Kakao wants 200 within 3 s whatever happens, so the
 * request only records the unlink durably; the work happens right after, off the request.
 */
@RestController
class KakaoUnlinkController {

	private static final Logger log = LoggerFactory.getLogger(KakaoUnlinkController.class);

	private final KakaoUnlinkQueue queue;
	private final byte[] expected;

	KakaoUnlinkController(KakaoUnlinkQueue queue, @Value("${auth.kakao.admin-key:}") String adminKey) {
		this.queue = queue;
		this.expected = adminKey.isBlank() ? null : ("KakaoAK " + adminKey).getBytes(StandardCharsets.UTF_8);
	}

	@RequestMapping(path = "/social/kakao/unlink", method = { RequestMethod.GET, RequestMethod.POST })
	ResponseEntity<Void> unlink(@RequestHeader(name = "Authorization", required = false) String authorization,
			@RequestParam(name = "user_id", required = false) String kakaoUserId,
			@RequestParam(name = "referrer_type", required = false) String referrer) {
		if (expected == null) {
			log.warn("Kakao unlink webhook called but KAKAO_ADMIN_KEY is not configured");
			return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE).build();
		}
		if (authorization == null
				|| !MessageDigest.isEqual(expected, authorization.getBytes(StandardCharsets.UTF_8))) {
			return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
		}
		// Only a local append (no database), then the queue's worker signs the account out within seconds. If the
		// append fails the request fails too (not acknowledged), rather than answer 200 for an unrecorded unlink.
		if (kakaoUserId != null && !queue.add(kakaoUserId, referrer)) {
			log.warn("Kakao unlink webhook: user_id is not a Kakao member number; ignored");
		}
		return ResponseEntity.ok().build();
	}
}
