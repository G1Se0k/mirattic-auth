package com.mirattic.auth.config;

import static org.springframework.security.config.Customizer.withDefaults;

import java.time.Clock;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import com.mirattic.auth.account.AccountService;
import com.mirattic.auth.account.Devices;
import com.mirattic.auth.account.SecurityEvents;
import com.mirattic.auth.account.SocialLogin;
import com.mirattic.auth.account.SocialReauth;
import org.springframework.boot.security.oauth2.server.authorization.autoconfigure.servlet.OAuth2AuthorizationServerProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.security.oauth2.core.oidc.endpoint.OidcParameterNames;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.context.SecurityContextHolderFilter;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.security.web.header.writers.ReferrerPolicyHeaderWriter.ReferrerPolicy;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;

@Configuration
class SecurityConfig {

	/** OAuth2/OIDC endpoints. Same as Spring Boot's default authorization-server chain. */
	@Bean
	@Order(1)
	SecurityFilterChain authorizationServerChain(HttpSecurity http, AccountClaims accountClaims) throws Exception {
		MediaTypeRequestMatcher html = new MediaTypeRequestMatcher(MediaType.TEXT_HTML);
		html.setIgnoredMediaTypes(Set.of(MediaType.ALL));
		return http
				.oauth2AuthorizationServer(as -> {
					http.securityMatcher(as.getEndpointsMatcher());
					// UserInfo reads the account live (ID token claims are a login-time snapshot), limited to
					// the presented access token's scopes (a refresh may have narrowed them).
					as.oidc(o -> o.userInfoEndpoint(u -> u.userInfoMapper(ctx -> new OidcUserInfo(
							accountClaims.forActive(ctx.getAuthorization().getPrincipalName(),
									ctx.getAccessToken().getScopes(), OAuth2ErrorCodes.INVALID_TOKEN)))));
				})
				.authorizeHttpRequests(a -> a.anyRequest().authenticated())
				.addFilterAfter(new FreshLoginFilter(Clock.systemUTC()), SecurityContextHolderFilter.class)
				.oauth2ResourceServer(r -> r.jwt(withDefaults()))
				.exceptionHandling(e -> e.defaultAuthenticationEntryPointFor(
						new LoginUrlAuthenticationEntryPoint("/login"), html))
				.build();
	}

	/** Browser login (the Auth SSO session) and everything else. */
	@Bean
	@Order(2)
	SecurityFilterChain defaultChain(HttpSecurity http, SocialLogin socialLogin,
			ClientRegistrationRepository registrations, Devices devices, SecurityEvents events) throws Exception {
		return http
				.authorizeHttpRequests(a -> a
						.requestMatchers("/actuator/health", "/privacy", "/login", "/signup", "/password/reset",
								"/password/reset/confirm", "/error").permitAll()
						.requestMatchers("/style.css", "/fonts/**", "/mark.svg", "/favicon-32.png",
								"/apple-touch-icon.png").permitAll()
						.anyRequest().authenticated())
				.formLogin(f -> f.loginPage("/login")
						.successHandler(devices.recording(new SavedRequestAwareAuthenticationSuccessHandler()))
						.failureHandler(events.failedPasswords(new SimpleUrlAuthenticationFailureHandler("/login?error"))))
				// Kakao / Naver: /oauth2/authorization/{kakao|naver} → provider → /login/oauth2/code/{id}.
				.oauth2Login(o -> o.loginPage("/login").failureHandler(SocialLogin.failureHandler())
						.successHandler(devices.recording(new SavedRequestAwareAuthenticationSuccessHandler()))
						.authorizationEndpoint(a -> a.authorizationRequestResolver(new SocialReauth(registrations)))
						.userInfoEndpoint(u -> u.userService(socialLogin)))
				// Reset links carry a token in the URL; never leak it through Referer.
				.headers(h -> h.referrerPolicy(r -> r.policy(ReferrerPolicy.NO_REFERRER)))
				.build();
	}

	@Bean
	PasswordEncoder passwordEncoder() {
		return PasswordEncoderFactories.createDelegatingPasswordEncoder();
	}

	/**
	 * Login by LOCAL identity (normalized email). The principal name is users.id, so every token's
	 * `sub` is the global Mirattic UID, never the email.
	 */
	@Bean
	UserDetailsService userDetailsService(JdbcOperations jdbc) {
		return email -> {
			List<User> found = jdbc.query("""
					SELECT u.id, u.status, i.password_hash
					FROM user_identities i JOIN users u ON u.id = i.user_id
					WHERE i.provider = 'LOCAL' AND i.subject = ?
					""", (rs, n) -> (User) User.withUsername(rs.getString("id"))
					.password(rs.getString("password_hash"))
					.disabled(!"ACTIVE".equals(rs.getString("status")))
					.build(), email.trim().toLowerCase(Locale.ROOT));
			if (found.isEmpty()) {
				throw new UsernameNotFoundException("not found");
			}
			return found.getFirst();
		};
	}

	/**
	 * Every JWT (access / ID token) is minted only for an ACTIVE account. This is the one place all
	 * grants pass through, so a disabled/deleted user can neither exchange a code (e.g. from a
	 * still-open SSO session) nor refresh. ID tokens also get name/email per granted scope.
	 */
	@Bean
	OAuth2TokenCustomizer<JwtEncodingContext> accountClaimsCustomizer(AccountClaims accountClaims) {
		return context -> {
			Map<String, Object> claims = accountClaims.forActive(context.getPrincipal().getName(),
					context.getAuthorizedScopes(), OAuth2ErrorCodes.INVALID_GRANT);
			if (OidcParameterNames.ID_TOKEN.equals(context.getTokenType().getValue())) {
				context.getClaims().claims(c -> c.putAll(claims));
			} else if (OAuth2TokenType.ACCESS_TOKEN.equals(context.getTokenType())) {
				// When the login behind this token happened (as the ID token's auth_time; a refresh keeps the original
				// login's time). Products use it to reject tokens of logins older than a boundary, e.g. Flow after a
				// withdrawal and re-join (docs/oauth-oidc.md).
				Instant authTime = AccountService.signInTime(context.getPrincipal());
				if (!Instant.EPOCH.equals(authTime)) {
					// Date, as SAS does for the ID token: written as epoch seconds, and allowed by the Jackson type
					// allowlist that stores the token's claims with the authorization (a Long is not).
					context.getClaims().claim("auth_time", Date.from(authTime));
				}
			}
		};
	}

	/** Refresh tokens are stored hashed, which only works with rotation (see HashedTokenAuthorizationService). */
	@Bean
	OAuth2AuthorizationService authorizationService(JdbcOperations jdbc, RegisteredClientRepository clients,
			OAuth2AuthorizationServerProperties properties, PlatformTransactionManager transactionManager,
			SecurityEvents events) {
		properties.getClient().forEach((name, client) -> {
			if (client.getToken().isReuseRefreshTokens()) {
				throw new IllegalStateException("Client '" + name + "' must set token.reuse-refresh-tokens: false");
			}
		});
		return new HashedTokenAuthorizationService(new JdbcOAuth2AuthorizationService(jdbc, clients), jdbc,
				new TransactionTemplate(transactionManager), (userId, clientId) -> {
					RegisteredClient client = clients.findById(clientId);
					events.record(userId, SecurityEvents.Type.TOKEN_REUSE, client == null ? null : client.getClientName());
				});
	}

	@Bean
	OAuth2AuthorizationConsentService authorizationConsentService(JdbcOperations jdbc,
			RegisteredClientRepository clients) {
		return new JdbcOAuth2AuthorizationConsentService(jdbc, clients);
	}
}
