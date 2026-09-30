package com.mirattic.auth.account;

import jakarta.servlet.http.HttpServletRequest;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.Map;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;

/**
 * Re-authentication through Kakao / Naver. When the client asked for `prompt=login` (FreshLoginFilter ended the
 * old sign-in and the request waits in the session), the provider must ask for credentials too — otherwise its
 * own session signs the user straight back in and the new `auth_time` proves nothing.
 * Also when adding Kakao / Naver to an account (SocialLogin link mode): the user picks which provider account.
 * Kakao: `prompt=login`. Naver: `auth_type=reauthenticate`. Google has no way to demand its login screen (its
 * `prompt` takes none | consent | select_account only), so it gets `select_account`: the user at least picks the
 * account again, and an unlocked browser signed in to Google passes (docs/security.md).
 */
public class SocialReauth implements OAuth2AuthorizationRequestResolver {

	private final DefaultOAuth2AuthorizationRequestResolver delegate;
	private final HttpSessionRequestCache requestCache = new HttpSessionRequestCache();

	public SocialReauth(ClientRegistrationRepository registrations) {
		this.delegate = new DefaultOAuth2AuthorizationRequestResolver(registrations, "/oauth2/authorization");
	}

	@Override
	public OAuth2AuthorizationRequest resolve(HttpServletRequest request) {
		return withReauth(request, delegate.resolve(request));
	}

	@Override
	public OAuth2AuthorizationRequest resolve(HttpServletRequest request, String registrationId) {
		return withReauth(request, delegate.resolve(request, registrationId));
	}

	private OAuth2AuthorizationRequest withReauth(HttpServletRequest request, OAuth2AuthorizationRequest auth) {
		if (auth == null) {
			return null;
		}
		SavedRequest saved = requestCache.getRequest(request, null);
		String[] prompt = saved == null ? null : saved.getParameterMap().get("prompt");
		// OIDC prompt is a space-separated list ("login consent" asks for a login too).
		boolean linking = request.getSession(false) != null
				&& request.getSession(false).getAttribute(SocialLogin.LINK) != null;
		if (!linking && (prompt == null || !Arrays.asList(prompt[0].trim().split("\\s+")).contains("login"))) {
			return auth;
		}
		Map<String, Object> extra = new LinkedHashMap<>(auth.getAdditionalParameters());
		switch (String.valueOf(auth.getAttributes().get(OAuth2ParameterNames.REGISTRATION_ID))) {
			case "kakao" -> extra.put("prompt", "login");
			case "naver" -> extra.put("auth_type", "reauthenticate");
			case "google" -> extra.put("prompt", "select_account");
			default -> { }
		}
		return OAuth2AuthorizationRequest.from(auth).additionalParameters(extra).build();
	}
}
