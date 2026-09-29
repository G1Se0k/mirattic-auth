package com.mirattic.auth.account;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.MailException;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Component;

/** Called from the async {@link AccountService#requestPasswordReset}. */
@Component
class PasswordResetMailer {

	private static final Logger log = LoggerFactory.getLogger(PasswordResetMailer.class);

	private final JavaMailSender mailSender;
	private final String from;
	private final String baseUrl;

	PasswordResetMailer(JavaMailSender mailSender, @Value("${auth.mail.from}") String from,
			@Value("${spring.security.oauth2.authorizationserver.issuer}") String baseUrl) {
		this.mailSender = mailSender;
		this.from = from;
		this.baseUrl = baseUrl;
	}

	void send(String to, String token) {
		SimpleMailMessage message = new SimpleMailMessage();
		message.setFrom(from);
		message.setTo(to);
		message.setSubject("Mirattic 비밀번호 재설정");
		message.setText("""
				아래 링크에서 새 비밀번호를 설정하세요. 링크는 30분 동안 한 번만 사용할 수 있습니다.

				%s/password/reset/confirm?token=%s

				요청하지 않았다면 이 메일을 무시하세요.
				""".formatted(baseUrl, token));
		try {
			mailSender.send(message);
		} catch (MailException e) {
			// Never log the message itself: it contains the reset token.
			log.warn("Password reset mail failed: {}", e.getClass().getSimpleName());
		}
	}
}
