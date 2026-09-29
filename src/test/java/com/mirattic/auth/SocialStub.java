package com.mirattic.auth;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

/** Stand-in for Kakao's and Naver's token and user-info endpoints (JDK HTTP server, one per test JVM). */
final class SocialStub {

	private static final HttpServer SERVER;
	/** code → user-info JSON; the access token is "at-" + code. */
	private static final Map<String, String> PROFILES = new ConcurrentHashMap<>();

	static {
		try {
			SERVER = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
			SERVER.createContext("/token", ex -> {
				String body = new String(ex.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
				String code = null;
				for (String pair : body.split("&")) {
					if (pair.startsWith("code=")) {
						code = URLDecoder.decode(pair.substring(5), StandardCharsets.UTF_8);
					}
				}
				if (code == null || !PROFILES.containsKey(code)) {
					send(ex, 400, "{\"error\":\"invalid_grant\"}");
					return;
				}
				send(ex, 200, "{\"access_token\":\"at-" + code + "\",\"token_type\":\"bearer\",\"expires_in\":3600}");
			});
			SERVER.createContext("/me", ex -> {
				String auth = String.valueOf(ex.getRequestHeaders().getFirst("Authorization"));
				String profile = PROFILES.get(auth.replace("Bearer at-", ""));
				send(ex, profile == null ? 401 : 200, profile == null ? "{}" : profile);
			});
			SERVER.start();
		} catch (IOException e) {
			throw new IllegalStateException(e);
		}
	}

	private SocialStub() {
	}

	static String url(String path) {
		return "http://127.0.0.1:" + SERVER.getAddress().getPort() + path;
	}

	/** A provider sign-in that will return this user-info JSON; returns the authorization code. */
	static String code(String userInfoJson) {
		String code = UUID.randomUUID().toString();
		PROFILES.put(code, userInfoJson);
		return code;
	}

	private static void send(HttpExchange ex, int status, String body) throws IOException {
		byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
		ex.getResponseHeaders().set("Content-Type", "application/json;charset=UTF-8");
		ex.sendResponseHeaders(status, bytes.length);
		ex.getResponseBody().write(bytes);
		ex.close();
	}
}
