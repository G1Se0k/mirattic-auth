package com.mirattic.auth.i18n;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import java.util.List;
import java.util.Locale;
import org.springframework.web.util.UriComponentsBuilder;

/**
 * Which of Korean, English, Japanese a request gets: `?lang=`, then the cookie that remembers it, then the
 * browser's Accept-Language (English if it names none of the three; Korean if it names nothing at all).
 */
public final class Lang {

	public static final List<String> ALL = List.of("ko", "en", "ja");
	public static final String COOKIE = "lang";

	private Lang() {
	}

	/** "ko" | "en" | "ja", or null. */
	static String valid(String code) {
		return code != null && ALL.contains(code) ? code : null;
	}

	public static Locale of(HttpServletRequest request) {
		String code = valid(queryLang(request));
		if (code == null && request.getCookies() != null) {
			for (Cookie c : request.getCookies()) {
				if (COOKIE.equals(c.getName())) {
					code = valid(c.getValue());
				}
			}
		}
		return Locale.of(code != null ? code : fromHeader(request.getHeader("Accept-Language")));
	}

	/** `lang` from the URL's query only: reading request parameters would decode a posted form before the encoding filter. */
	static String queryLang(HttpServletRequest request) {
		String query = request.getQueryString();
		return query == null ? null
				: UriComponentsBuilder.newInstance().query(query).build().getQueryParams().getFirst("lang");
	}

	static String fromHeader(String header) {
		if (header == null || header.isBlank()) {
			return "ko";
		}
		try {
			for (Locale.LanguageRange r : Locale.LanguageRange.parse(header)) {
				String primary = r.getRange().split("-")[0];
				if (r.getWeight() > 0 && ALL.contains(primary)) {
					return primary;
				}
			}
		} catch (IllegalArgumentException malformed) {
			// falls through to English
		}
		return "en";
	}
}
