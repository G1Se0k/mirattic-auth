package com.mirattic.auth;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * Stand-in for Kakao's, Naver's and Google's token and user-info endpoints (Google's with a signed ID token and its
 * JWK set), and for the products' account-deletion and admin-read endpoints (JDK HTTP server, one per test JVM).
 */
final class SocialStub {

	private static final HttpServer SERVER;
	/** code → user-info JSON; the access token is "at-" + code. */
	private static final Map<String, String> PROFILES = new ConcurrentHashMap<>();
	/** code → Google ID token issued with it. */
	private static final Map<String, String> ID_TOKENS = new ConcurrentHashMap<>();
	static final String GOOGLE_ISSUER = "https://accounts.google.com";
	private static final RSAKey GOOGLE_KEY;
	/** Product ("flow" | "sync") → the answer its deletion endpoint gives: status and body. */
	static final Map<String, Map.Entry<Integer, String>> DELETION = new ConcurrentHashMap<>();
	/** Deletion orders received, in order: product + " " + bearer token. */
	static final List<String> DELETIONS = new CopyOnWriteArrayList<>();
	/** Runs while a product's deletion endpoint is handling the order (what Auth looks like mid-deletion). */
	static volatile Runnable duringDeletion = () -> { };
	/** Admin reads received: product + " " + path + " " + bearer token. Sync answers; Flow is down (500). */
	static final List<String> ADMIN_READS = new CopyOnWriteArrayList<>();
	/** A UID in Sync's admin answers (the console links it). */
	static final String ADMIN_ROW_UID = "b0000000-0000-4000-8000-0000000000b1";

	static {
		try {
			GOOGLE_KEY = new RSAKeyGenerator(2048).keyID("google-test").generate();
		} catch (JOSEException e) {
			throw new IllegalStateException(e);
		}
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
				String idToken = ID_TOKENS.get(code);
				send(ex, 200, "{\"access_token\":\"at-" + code + "\",\"token_type\":\"bearer\",\"expires_in\":3600"
						+ (idToken == null ? "" : ",\"id_token\":\"" + idToken + "\"") + "}");
			});
			SERVER.createContext("/jwks", ex -> send(ex, 200, new JWKSet(GOOGLE_KEY.toPublicJWK()).toString()));
			SERVER.createContext("/me", ex -> {
				String auth = String.valueOf(ex.getRequestHeaders().getFirst("Authorization"));
				String profile = PROFILES.get(auth.replace("Bearer at-", ""));
				send(ex, profile == null ? 401 : 200, profile == null ? "{}" : profile);
			});
			for (String product : new String[] {"flow", "sync"}) {
				SERVER.createContext("/" + product + "/delete", ex -> {
					DELETIONS.add(product + " " + String.valueOf(ex.getRequestHeaders().getFirst("Authorization"))
							.replace("Bearer ", ""));
					duringDeletion.run();
					Map.Entry<Integer, String> answer = DELETION.getOrDefault(product, Map.entry(204, ""));
					if (answer.getKey() == 204) {
						ex.sendResponseHeaders(204, -1);
						ex.close();
					} else {
						send(ex, answer.getKey(), answer.getValue());
					}
				});
			}
			for (String product : new String[] {"flow", "sync"}) {
				SERVER.createContext("/" + product + "/admin", ex -> {
					ADMIN_READS.add(product + " " + ex.getRequestURI().getPath().replace("/" + product + "/admin", "")
							+ " " + String.valueOf(ex.getRequestHeaders().getFirst("Authorization")).replace("Bearer ", ""));
					if ("flow".equals(product)) {
						send(ex, 500, "{}");
					} else {
						send(ex, 200, "{\"facts\":[[\"방\",\"3<b>\"]],\"tables\":[{\"title\":\"친구\","
								+ "\"columns\":[\"이름\",\"UID\"],\"rows\":[[\"" + ADMIN_ROW_UID.replace("b1", "c1") + "\",\"" + ADMIN_ROW_UID + "\"]]}],"
								+ "\"more\":true}");
					}
				});
			}
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

	/**
	 * A Google sign-in: an ID token for `clientId` answering `nonce` (from the authorization request), and UserInfo
	 * with the same `sub`. Returns the authorization code.
	 */
	static String google(String clientId, String nonce, String sub, String email, boolean verified, String name) {
		String code = code("{\"sub\":\"%s\",\"email\":\"%s\",\"email_verified\":%s,\"name\":\"%s\"}"
				.formatted(sub, email, verified, name));
		try {
			JWTClaimsSet claims = new JWTClaimsSet.Builder().issuer(GOOGLE_ISSUER).audience(clientId).subject(sub)
					.issueTime(new Date()).expirationTime(new Date(System.currentTimeMillis() + 3_600_000))
					.claim("nonce", nonce).claim("email", email).claim("email_verified", verified).claim("name", name)
					.build();
			SignedJWT jwt = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(GOOGLE_KEY.getKeyID()).build(),
					claims);
			jwt.sign(new RSASSASigner(GOOGLE_KEY));
			ID_TOKENS.put(code, jwt.serialize());
		} catch (JOSEException e) {
			throw new IllegalStateException(e);
		}
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
