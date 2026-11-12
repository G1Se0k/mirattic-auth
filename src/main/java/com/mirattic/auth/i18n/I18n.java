package com.mirattic.auth.i18n;

import com.mirattic.auth.account.AccountException;
import com.mirattic.auth.account.SecurityEvents;
import jakarta.servlet.http.HttpServletRequest;
import java.util.Arrays;
import org.springframework.context.MessageSource;
import org.springframework.context.i18n.LocaleContextHolder;
import org.springframework.context.annotation.Bean;
import org.springframework.stereotype.Component;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;
import org.springframework.web.servlet.LocaleResolver;
import org.springframework.web.util.UriComponentsBuilder;
import org.springframework.context.annotation.Configuration;
import java.util.Locale;

/** Texts in the request's language; pages reach it as `@i18n`. */
@Component("i18n")
public class I18n {

	private final MessageSource messages;

	I18n(MessageSource messages) {
		this.messages = messages;
	}

	public String msg(String key, Object... args) {
		return messages.getMessage(key, args, LocaleContextHolder.getLocale());
	}

	public String msg(AccountException e) {
		return messages.getMessage(e.key(), e.args(), e.key(), LocaleContextHolder.getLocale());
	}

	public String event(SecurityEvents.Type type) {
		return msg("event." + type.name());
	}

	/**
	 * A stored or computed "Chrome · Mac" / "카카오 · Chrome · Mac": each part with a translation gets it
	 * (stored rows keep the Korean they were written in), the rest (Chrome, Mac, a product's name) stays.
	 */
	public String label(String label) {
		if (label == null) {
			return null;
		}
		return String.join(" · ", Arrays.stream(label.split(" · ", -1)).map(part -> messages
				.getMessage("label." + part.replace(' ', '_'), null, part, LocaleContextHolder.getLocale())).toList());
	}

	/**
	 * The address of this page with `lang` set, as a GET: its own query only, never a form. A page shown after a
	 * failed POST goes back to its GET route (the account page, or the reset page with its one `token`).
	 */
	public String switchUrl(String lang) {
		HttpServletRequest r = ((ServletRequestAttributes) RequestContextHolder.currentRequestAttributes())
				.getRequest();
		String path = r.getRequestURI();
		boolean post = "POST".equals(r.getMethod());
		UriComponentsBuilder b = UriComponentsBuilder.newInstance().path(post && path.startsWith("/account") ? "/account" : path);
		if (!post && r.getQueryString() != null) {
			b.query(r.getQueryString());
		} else if (post && path.equals("/password/reset/confirm") && r.getParameter("token") != null) {
			b.queryParam("token", java.net.URLEncoder.encode(r.getParameter("token"), java.nio.charset.StandardCharsets.UTF_8));
		}
		return b.replaceQueryParam("lang", lang).build().toUriString();
	}

	@Configuration
	static class Resolver {
		@Bean
		LocaleResolver localeResolver() {
			return new LocaleResolver() {
				@Override
				public Locale resolveLocale(HttpServletRequest request) {
					return Lang.of(request);
				}

				@Override
				public void setLocale(HttpServletRequest request, jakarta.servlet.http.HttpServletResponse response,
						Locale locale) {
					throw new UnsupportedOperationException();
				}
			};
		}
	}
}
