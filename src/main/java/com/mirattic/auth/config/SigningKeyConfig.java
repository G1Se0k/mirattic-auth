package com.mirattic.auth.config;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.ArrayList;
import java.util.List;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;

/**
 * The RS256 signing key lives in a JWK JSON file outside the source tree, so it survives restarts
 * (docs/deployment.md). `kid` is the RFC 7638 thumbprint, stable for the same key.
 */
@Configuration
class SigningKeyConfig {

	private static final Logger log = LoggerFactory.getLogger(SigningKeyConfig.class);

	/**
	 * JWKS (`/oauth2/jwks`, token verification): the current key and, during a rotation, the previous one (public
	 * part only), so tokens signed before the rotation stay valid until they expire (docs/deployment.md "Signing Keys").
	 */
	@Bean
	JWKSource<SecurityContext> jwkSource(RSAKey current,
			@Value("${auth.signing-key.previous-path:}") String previousPath) throws Exception {
		List<JWK> keys = new ArrayList<>(List.of(current));
		if (!previousPath.isBlank() && Files.exists(Path.of(previousPath))) {
			RSAKey previous = RSAKey.parse(Files.readString(Path.of(previousPath)));
			if (!previous.getKeyID().equals(current.getKeyID())) {
				keys.add(previous.toPublicJWK());
				log.info("Publishing the previous signing key kid={} alongside the current kid={}", previous.getKeyID(),
						current.getKeyID());
			}
		}
		return new ImmutableJWKSet<>(new JWKSet(keys));
	}

	/** Every JWT Auth mints (SAS tokens, account-deletion orders) is signed with the current key only. */
	@Bean
	JwtEncoder jwtEncoder(JWKSource<SecurityContext> jwkSource, RSAKey current) {
		NimbusJwtEncoder encoder = new NimbusJwtEncoder(jwkSource);
		encoder.setJwkSelector(candidates -> candidates.stream()
				.filter(k -> current.getKeyID().equals(k.getKeyID())).findFirst()
				.orElseThrow(() -> new IllegalStateException("current signing key not in the JWK source")));
		return encoder;
	}

	/** The key tokens are signed with. */
	@Bean
	RSAKey currentSigningKey(@Value("${auth.signing-key.path}") Path path,
			@Value("${auth.signing-key.generate-if-missing:false}") boolean generateIfMissing) throws Exception {
		RSAKey key;
		if (Files.exists(path)) {
			key = RSAKey.parse(Files.readString(path));
		} else if (generateIfMissing) {
			key = new RSAKeyGenerator(2048).keyIDFromThumbprint(true).generate();
			if (path.getParent() != null) {
				Files.createDirectories(path.getParent());
			}
			Files.writeString(path, key.toJSONString());
			Files.setPosixFilePermissions(path, PosixFilePermissions.fromString("rw-------"));
			log.warn("Generated a new signing key at {} (kid={}).", path, key.getKeyID());
		} else {
			throw new IllegalStateException("Signing key not found at " + path + " (AUTH_SIGNING_KEY_PATH)");
		}
		if (!key.isPrivate() || key.getKeyID() == null || key.getKeyID().isBlank()) {
			throw new IllegalStateException("Signing key at " + path + " must be a private RSA JWK with a kid");
		}
		return key;
	}
}
