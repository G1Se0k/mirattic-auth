package com.mirattic.auth.account;

import java.time.Instant;
import java.util.List;
import java.util.UUID;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.stereotype.Component;

/**
 * Back-channel orders from Auth to a product (account deletion, admin reads): a one-minute JWT signed with Auth's key,
 * for one product (`aud`), with a `purpose` the product's endpoint requires and no `scope`, so it is never an access
 * token. Products verify it with the JWKS.
 */
@Component
public class ProductOrders {

	private final String issuer;
	private final JwtEncoder encoder;

	ProductOrders(@Value("${spring.security.oauth2.authorizationserver.issuer}") String issuer, JwtEncoder encoder) {
		this.issuer = issuer;
		this.encoder = encoder;
	}

	public String sign(String audience, String subject, String purpose) {
		Instant now = Instant.now();
		JwtClaimsSet claims = JwtClaimsSet.builder().issuer(issuer).audience(List.of(audience)).subject(subject)
				.issuedAt(now).expiresAt(now.plusSeconds(60)).id(UUID.randomUUID().toString())
				.claim("purpose", purpose).build();
		return encoder.encode(JwtEncoderParameters.from(JwsHeader.with(SignatureAlgorithm.RS256).build(), claims))
				.getTokenValue();
	}
}
