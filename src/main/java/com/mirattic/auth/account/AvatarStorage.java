package com.mirattic.auth.account;

import java.net.URI;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnExpression;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.core.checksums.RequestChecksumCalculation;
import software.amazon.awssdk.core.checksums.ResponseChecksumValidation;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.S3Configuration;

/** The Cloudflare R2 client (S3 API). Exists only when `auth.avatar.endpoint` is set. */
@Configuration
@ConditionalOnExpression("!'${auth.avatar.endpoint:}'.isEmpty()")
class AvatarStorage {

	@Bean
	S3Client avatarS3(@Value("${auth.avatar.endpoint}") String endpoint,
			@Value("${auth.avatar.access-key}") String accessKey, @Value("${auth.avatar.secret-key}") String secretKey) {
		return S3Client.builder().endpointOverride(URI.create(endpoint)).region(Region.of("auto"))
				.credentialsProvider(StaticCredentialsProvider.create(AwsBasicCredentials.create(accessKey, secretKey)))
				.serviceConfiguration(S3Configuration.builder().pathStyleAccessEnabled(true).build())
				// R2 does not take the SDK's default CRC checksums on every call.
				.requestChecksumCalculation(RequestChecksumCalculation.WHEN_REQUIRED)
				.responseChecksumValidation(ResponseChecksumValidation.WHEN_REQUIRED).build();
	}
}
