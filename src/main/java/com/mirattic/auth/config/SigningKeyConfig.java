package com.mirattic.auth.config;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * The RS256 signing key lives in a JWK JSON file outside the source tree, so it survives restarts
 * (docs/deployment.md). `kid` is the RFC 7638 thumbprint, stable for the same key.
 */
@Configuration
class SigningKeyConfig {

	private static final Logger log = LoggerFactory.getLogger(SigningKeyConfig.class);

	@Bean
	JWKSource<SecurityContext> jwkSource(@Value("${auth.signing-key.path}") Path path,
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
			log.warn("Generated a new signing key at {} (kid={}). Dev only.", path, key.getKeyID());
		} else {
			throw new IllegalStateException("Signing key not found at " + path + " (AUTH_SIGNING_KEY_PATH)");
		}
		if (!key.isPrivate() || key.getKeyID() == null || key.getKeyID().isBlank()) {
			throw new IllegalStateException("Signing key at " + path + " must be a private RSA JWK with a kid");
		}
		// ponytail: single key. Rotation = publish previous public key alongside current (Phase 7).
		return new ImmutableJWKSet<>(new JWKSet(key));
	}
}
