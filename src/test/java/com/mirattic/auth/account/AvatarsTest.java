package com.mirattic.auth.account;

import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.awt.image.BufferedImage;
import java.io.ByteArrayOutputStream;
import javax.imageio.ImageIO;
import org.junit.jupiter.api.Test;

class AvatarsTest {

	@Test
	void notAnImageTooBigOrTooManyPixelsIsRefused() throws Exception {
		assertThatThrownBy(() -> Avatars.normalize("<?php echo 1;".getBytes())).hasMessageContaining("JPG");
		assertThatThrownBy(() -> Avatars.normalize(new byte[11 * 1024 * 1024])).hasMessageContaining("10MB");
		ByteArrayOutputStream big = new ByteArrayOutputStream();
		ImageIO.write(new BufferedImage(5000, 5000, BufferedImage.TYPE_BYTE_GRAY), "png", big);
		assertThatThrownBy(() -> Avatars.normalize(big.toByteArray())).hasMessageContaining("너무 큽니다");
	}
}
