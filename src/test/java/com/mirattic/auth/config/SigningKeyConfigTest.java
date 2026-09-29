package com.mirattic.auth.config;

import static org.assertj.core.api.Assertions.assertThat;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKMatcher;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;

/** Rotation (deploy/rotate-signing-key.sh): the previous key is published, never used to sign. */
class SigningKeyConfigTest {

	private final SigningKeyConfig config = new SigningKeyConfig();

	@Test
	void duringARotationBothKeysArePublishedAndOnlyTheNewOneSigns(@TempDir Path dir) throws Exception {
		RSAKey old = new RSAKeyGenerator(2048).keyIDFromThumbprint(true).generate();
		Files.writeString(dir.resolve("previous.json"), old.toJSONString());
		RSAKey current = config.currentSigningKey(dir.resolve("current.json"), true); // generated, as after `rotate`

		JWKSource<SecurityContext> source = config.jwkSource(current, dir.resolve("previous.json").toString());
		List<JWK> published = source.get(new JWKSelector(new JWKMatcher.Builder().build()), null);
		assertThat(published).extracting(JWK::getKeyID).containsExactly(current.getKeyID(), old.getKeyID());
		assertThat(published.get(1).isPrivate()).isFalse();

		JwtEncoder encoder = config.jwtEncoder(source, current);
		String token = sign(encoder);
		assertThat(com.nimbusds.jwt.SignedJWT.parse(token).getHeader().getKeyID()).isEqualTo(current.getKeyID());

		// A token from before the rotation still verifies; after `retire` it no longer does.
		String before = sign(new NimbusJwtEncoder(new com.nimbusds.jose.jwk.source.ImmutableJWKSet<>(
				new com.nimbusds.jose.jwk.JWKSet(old))));
		NimbusJwtDecoder decoder = NimbusJwtDecoder.withJwkSource(source).build();
		assertThat(decoder.decode(before).getSubject()).isEqualTo("u");
		assertThat(decoder.decode(token).getSubject()).isEqualTo("u");

		JWKSource<SecurityContext> retired = config.jwkSource(current, "");
		assertThat(retired.get(new JWKSelector(new JWKMatcher.Builder().build()), null)).hasSize(1);
		org.assertj.core.api.Assertions.assertThatThrownBy(() -> NimbusJwtDecoder.withJwkSource(retired).build().decode(before))
				.isInstanceOf(org.springframework.security.oauth2.jwt.JwtException.class);
	}

	private static String sign(JwtEncoder encoder) {
		JwtClaimsSet claims = JwtClaimsSet.builder().subject("u").issuedAt(Instant.now())
				.expiresAt(Instant.now().plusSeconds(60)).build();
		return encoder.encode(JwtEncoderParameters.from(JwsHeader.with(SignatureAlgorithm.RS256).build(), claims))
				.getTokenValue();
	}
}
