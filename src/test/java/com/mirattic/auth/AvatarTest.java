package com.mirattic.auth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.multipart;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;

import com.jayway.jsonpath.JsonPath;
import jakarta.servlet.http.Cookie;
import java.awt.image.BufferedImage;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import javax.imageio.ImageIO;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockMultipartFile;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import software.amazon.awssdk.core.sync.RequestBody;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.DeleteObjectRequest;
import software.amazon.awssdk.services.s3.model.PutObjectRequest;

class AvatarTest extends IntegrationTest {

	@DynamicPropertySource
	static void r2(DynamicPropertyRegistry registry) {
		registry.add("auth.avatar.bucket", () -> "test-bucket");
		registry.add("auth.avatar.public-url", () -> "https://avatar.test/");
	}

	@MockitoBean
	S3Client s3;

	private static byte[] image(String format, int w, int h) throws Exception {
		ByteArrayOutputStream out = new ByteArrayOutputStream();
		ImageIO.write(new BufferedImage(w, h, BufferedImage.TYPE_INT_RGB), format, out);
		return out.toByteArray();
	}

	@Test
	void uploadIsReencodedAsASquareJpegAndReplacedThenDeletedWithTheAccount() throws Exception {
		String email = email();
		String uid = signup(email, "password-1", "Pic");
		Cookie session = login(email, "password-1");

		mvc.perform(multipart("/account/avatar").file(new MockMultipartFile("file", "a.png", "image/png",
						image("png", 3000, 2000))).with(csrf()).cookie(session))
				.andExpect(redirectedUrl("/account?avatar"));
		String key = jdbc.queryForObject("SELECT avatar_key FROM users WHERE id = ?", String.class, uid);
		assertThat(key).matches("avatars/" + uid + "/[0-9a-f]{24}\\.jpg");
		var put = org.mockito.ArgumentCaptor.forClass(RequestBody.class);
		verify(s3).putObject(any(PutObjectRequest.class), put.capture());
		BufferedImage stored = ImageIO.read(new ByteArrayInputStream(
				put.getValue().contentStreamProvider().newStream().readAllBytes()));
		assertThat(stored.getWidth()).isEqualTo(512);
		assertThat(stored.getHeight()).isEqualTo(512);

		// The picture claim rides the profile scope only.
		String tokens = exchange(authorize(session, "openid profile"));
		assertThat(claims(JsonPath.read(tokens, "$.id_token"))).contains("\"picture\":\"https://avatar.test/" + key + "\"");
		assertThat(claims(JsonPath.read(exchange(authorize(session, "openid")), "$.id_token"))).doesNotContain("picture");

		// A second photo replaces the first; the old object is deleted.
		mvc.perform(multipart("/account/avatar").file(new MockMultipartFile("file", "b.jpg", "image/jpeg",
						image("jpg", 300, 300))).with(csrf()).cookie(session)).andExpect(redirectedUrl("/account?avatar"));
		assertThat(jdbc.queryForObject("SELECT avatar_key FROM users WHERE id = ?", String.class, uid)).isNotEqualTo(key);
		verify(s3).deleteObject(DeleteObjectRequest.builder().bucket("test-bucket").key(key).build());

		// Account deletion removes the object too (Flow / Sync stubs answer 204 in the deletion tests; here: remove()).
		mvc.perform(multipart("/account/avatar/remove").with(csrf()).cookie(session)).andExpect(redirectedUrl("/account?avatar"));
		assertThat(jdbc.queryForObject("SELECT avatar_key FROM users WHERE id = ?", String.class, uid)).isNull();
	}
}
