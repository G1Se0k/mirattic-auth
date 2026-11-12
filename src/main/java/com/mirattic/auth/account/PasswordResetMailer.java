package com.mirattic.auth.account;

import java.util.Locale;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.MessageSource;
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

	private final MessageSource messages;

	PasswordResetMailer(MessageSource messages, JavaMailSender mailSender, @Value("${auth.mail.from}") String from,
			@Value("${spring.security.oauth2.authorizationserver.issuer}") String baseUrl) {
		this.messages = messages;
		this.mailSender = mailSender;
		this.from = from;
		this.baseUrl = baseUrl;
	}

	void send(String to, String token, Locale locale) {
		SimpleMailMessage message = new SimpleMailMessage();
		message.setFrom(from);
		message.setTo(to);
		message.setSubject(messages.getMessage("mail.resetSubject", null, locale));
		message.setText(messages.getMessage("mail.resetBody", new Object[] { baseUrl + "/password/reset/confirm?token=" + token },
				locale));
		try {
			mailSender.send(message);
		} catch (MailException e) {
			// Never log the message itself: it contains the reset token.
			log.warn("Password reset mail failed: {}", e.getClass().getSimpleName());
		}
	}
}
