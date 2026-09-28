package com.mirattic.auth.config;

import static org.springframework.security.config.Customizer.withDefaults;

import java.util.List;
import java.util.Locale;
import java.util.Set;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;

@Configuration
class SecurityConfig {

	/** OAuth2/OIDC endpoints. Same as Spring Boot's default authorization-server chain. */
	@Bean
	@Order(1)
	SecurityFilterChain authorizationServerChain(HttpSecurity http) throws Exception {
		MediaTypeRequestMatcher html = new MediaTypeRequestMatcher(MediaType.TEXT_HTML);
		html.setIgnoredMediaTypes(Set.of(MediaType.ALL));
		return http
				.oauth2AuthorizationServer(as -> {
					http.securityMatcher(as.getEndpointsMatcher());
					as.oidc(withDefaults());
				})
				.authorizeHttpRequests(a -> a.anyRequest().authenticated())
				.oauth2ResourceServer(r -> r.jwt(withDefaults()))
				.exceptionHandling(e -> e.defaultAuthenticationEntryPointFor(
						new LoginUrlAuthenticationEntryPoint("/login"), html))
				.build();
	}

	/** Browser login (the Auth SSO session) and everything else. */
	@Bean
	@Order(2)
	SecurityFilterChain defaultChain(HttpSecurity http) throws Exception {
		return http
				.authorizeHttpRequests(a -> a
						.requestMatchers("/actuator/health").permitAll()
						.anyRequest().authenticated())
				.formLogin(withDefaults())
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

	@Bean
	OAuth2AuthorizationService authorizationService(JdbcOperations jdbc, RegisteredClientRepository clients) {
		return new JdbcOAuth2AuthorizationService(jdbc, clients);
	}

	@Bean
	OAuth2AuthorizationConsentService authorizationConsentService(JdbcOperations jdbc,
			RegisteredClientRepository clients) {
		return new JdbcOAuth2AuthorizationConsentService(jdbc, clients);
	}
}
