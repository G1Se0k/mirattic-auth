package com.mirattic.auth.i18n;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Properties;
import java.util.Set;
import java.util.TreeSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.springframework.core.io.ClassPathResource;

/** Korean, English and Japanese texts stay in step: same keys, same {n} places; every key a page uses exists. */
class MessagesTest {

	private static Properties load(String file) throws IOException {
		Properties p = new Properties();
		try (InputStream in = new ClassPathResource(file).getInputStream();
				var r = new java.io.InputStreamReader(in, java.nio.charset.StandardCharsets.UTF_8)) {
			p.load(r);
		}
		return p;
	}

	private static Set<String> places(String text) {
		Set<String> out = new TreeSet<>();
		Matcher m = Pattern.compile("\\{\\d+}").matcher(text);
		while (m.find()) {
			out.add(m.group());
		}
		return out;
	}

	@Test
	void everyLanguageHasEveryKeyWithTheSamePlaces() throws IOException {
		Properties ko = load("messages.properties");
		for (String file : new String[] { "messages_en.properties", "messages_ja.properties" }) {
			Properties other = load(file);
			assertThat(other.stringPropertyNames()).as(file).isEqualTo(ko.stringPropertyNames());
			for (String key : ko.stringPropertyNames()) {
				assertThat(places(other.getProperty(key))).as(file + " " + key).isEqualTo(places(ko.getProperty(key)));
				assertThat(other.getProperty(key)).as(file + " " + key).isNotBlank();
			}
		}
	}

	@Test
	void everyKeyAPageUsesExists() throws IOException {
		Set<String> keys = load("messages.properties").stringPropertyNames();
		Pattern used = Pattern.compile("#\\{([A-Za-z][\\w.]*)|msg\\('([\\w.]+)'[,)]");
		try (Stream<Path> pages = Files.list(Path.of("src/main/resources/templates"))) {
			for (Path page : pages.filter(p -> !p.getFileName().toString().startsWith("admin")).toList()) {
				Matcher m = used.matcher(Files.readString(page));
				while (m.find()) {
					String key = m.group(1) != null ? m.group(1) : m.group(2);
					assertThat(keys).as(page + " uses " + key).contains(key);
				}
			}
		}
	}

	@Test
	void theBrowsersLanguageDecidesWhenNothingElseDoes() {
		assertThat(Lang.fromHeader(null)).isEqualTo("ko");
		assertThat(Lang.fromHeader("ja-JP,ja;q=0.9,en;q=0.8")).isEqualTo("ja");
		assertThat(Lang.fromHeader("fr-FR,fr;q=0.9,en;q=0.8")).isEqualTo("en");
		assertThat(Lang.fromHeader("de-DE,de;q=0.9")).isEqualTo("en");
		assertThat(Lang.fromHeader("ko;q=0, ja;q=0.5")).isEqualTo("ja");
	}

	@Test
	void aFailedAccountPostSwitchesBackToTheGetRoute() {
		var request = new org.springframework.mock.web.MockHttpServletRequest("POST", "/account/password");
		org.springframework.web.context.request.RequestContextHolder.setRequestAttributes(
				new org.springframework.web.context.request.ServletRequestAttributes(request));
		try {
			assertThat(new I18n(null).switchUrl("en")).isEqualTo("/account?lang=en");
		} finally {
			org.springframework.web.context.request.RequestContextHolder.resetRequestAttributes();
		}
	}
}
