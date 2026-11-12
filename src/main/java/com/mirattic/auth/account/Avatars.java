package com.mirattic.auth.account;

import java.awt.Color;
import java.awt.Graphics2D;
import java.awt.RenderingHints;
import java.awt.image.BufferedImage;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.SecureRandom;
import java.util.HexFormat;
import java.util.concurrent.Semaphore;
import javax.imageio.IIOException;
import javax.imageio.ImageIO;
import javax.imageio.ImageReader;
import javax.imageio.stream.ImageInputStream;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.support.TransactionTemplate;
import software.amazon.awssdk.core.sync.RequestBody;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.DeleteObjectRequest;
import software.amazon.awssdk.services.s3.model.PutObjectRequest;

/**
 * Profile photos (docs/api.md "Profile Photo"). The upload is decoded and re-encoded as a 512x512 JPEG, so EXIF
 * (location) and anything that is not pixels never reaches R2. Objects are served from a public R2 custom domain;
 * the key carries a random part, so a new photo is a new URL (no stale CDN cache) and a URL is not guessable.
 * Off (no R2 config): nothing is shown, stored or claimed.
 */
@Service
public class Avatars {

	private static final Logger log = LoggerFactory.getLogger(Avatars.class);
	static final int SIZE = 512;
	static final long MAX_BYTES = 10L * 1024 * 1024;
	/** Decoded size cap, against a small file that inflates to gigabytes. */
	private static final long MAX_PIXELS = 16_000_000L;
	private static final Semaphore DECODING = new Semaphore(1);
	private static final SecureRandom RANDOM = new SecureRandom();

	private final ObjectProvider<S3Client> s3;
	private final String bucket;
	private final String publicUrl;
	private final JdbcTemplate jdbc;
	private final TransactionTemplate tx;

	Avatars(ObjectProvider<S3Client> s3, @Value("${auth.avatar.bucket:}") String bucket,
			@Value("${auth.avatar.public-url:}") String publicUrl, JdbcTemplate jdbc, TransactionTemplate tx) {
		this.tx = tx;
		this.s3 = s3;
		this.bucket = bucket;
		this.publicUrl = publicUrl.endsWith("/") ? publicUrl.substring(0, publicUrl.length() - 1) : publicUrl;
		this.jdbc = jdbc;
	}

	public boolean enabled() {
		return !bucket.isBlank() && !publicUrl.isBlank() && s3.getIfAvailable() != null;
	}

	/** The photo's public URL, or null (no photo, or the feature is off). */
	public String url(String key) {
		return key == null || publicUrl.isBlank() ? null : publicUrl + "/" + key;
	}

	/** Replaces the user's photo. Throws AccountException for a bad file or a non-ACTIVE account. */
	public void set(String userId, byte[] upload) {
		if (!enabled()) {
			throw new AccountException("error.avatarOff");
		}
		byte[] jpeg;
		// One decode at a time: a 16 M pixel image is ~150 MB of buffers, and Auth's heap is small. Others are turned away.
		if (!DECODING.tryAcquire()) {
			throw new AccountException("error.avatarBusy");
		}
		try {
			jpeg = normalize(upload);
		} finally {
			DECODING.release();
		}
		String key = "avatars/" + userId + "/" + HexFormat.of().formatHex(randomBytes()) + ".jpg";
		String old;
		try {
			// The account row is locked for the whole swap: uploads, removals and the deletion fence of one account
			// run one at a time, so no photo is left without a database reference. (ponytail: R2 call under a row
			// lock; fine at this traffic, one account's own requests only.)
			old = tx.execute(s -> {
				var row = jdbc.queryForMap("SELECT status, avatar_key FROM users WHERE id = ? FOR UPDATE", userId);
				if (!"ACTIVE".equals(row.get("status"))) { // a deletion in progress must not gain a new photo
					throw new AccountException("error.avatarNow");
				}
				s3.getObject().putObject(PutObjectRequest.builder().bucket(bucket).key(key).contentType("image/jpeg")
						.cacheControl("public, max-age=31536000, immutable").build(), RequestBody.fromBytes(jpeg));
				jdbc.update("UPDATE users SET avatar_key = ?, updated_at = NOW(6) WHERE id = ?", key, userId);
				return (String) row.get("avatar_key");
			});
		} catch (RuntimeException e) {
			deleteQuietly(key); // rolled back: the new object has no reference (no-op if it was never put)
			throw e instanceof AccountException ? e : new AccountException("error.avatarSave");
		}
		deleteQuietly(old);
	}

	/**
	 * Removes the photo. Throws when R2 could not delete it, or R2 is not configured while a photo exists (account
	 * deletion then fails and is retried, instead of leaving a public photo behind).
	 */
	public void remove(String userId) {
		tx.executeWithoutResult(s -> {
			String old = jdbc.queryForObject("SELECT avatar_key FROM users WHERE id = ? FOR UPDATE", String.class, userId);
			if (old == null) {
				return;
			}
			if (bucket.isBlank() || s3.getIfAvailable() == null) {
				throw new AccountException("error.avatarRemove");
			}
			deleteObject(old);
			jdbc.update("UPDATE users SET avatar_key = NULL, updated_at = NOW(6) WHERE id = ?", userId);
		});
	}

	private void deleteObject(String key) {
		s3.getObject().deleteObject(DeleteObjectRequest.builder().bucket(bucket).key(key).build());
	}

	/** The replaced photo: a failed delete only leaves an orphan, logged. */
	private void deleteQuietly(String key) {
		if (key == null) {
			return;
		}
		try {
			deleteObject(key);
		} catch (RuntimeException e) {
			log.warn("Old avatar not deleted from R2: {}", e.getClass().getSimpleName());
		}
	}

	/** Centre-cropped square, 512x512 JPEG (transparency on white). */
	static byte[] normalize(byte[] upload) {
		if (upload.length == 0 || upload.length > MAX_BYTES) {
			throw new AccountException("error.avatarSize");
		}
		BufferedImage src = decode(upload);
		int side = Math.min(src.getWidth(), src.getHeight());
		BufferedImage img = src.getSubimage((src.getWidth() - side) / 2, (src.getHeight() - side) / 2, side, side);
		// Halve until the next halving would go below SIZE, then one last scale: a big photo shrinks without aliasing.
		// ponytail: EXIF orientation is not applied (a rotated phone photo stays rotated); read it if users hit it.
		while (img.getWidth() / 2 >= SIZE) {
			img = scale(img, img.getWidth() / 2);
		}
		img = scale(img, SIZE);
		ByteArrayOutputStream bytes = new ByteArrayOutputStream();
		try {
			if (!ImageIO.write(img, "jpg", bytes)) {
				throw new IOException("no jpg writer");
			}
		} catch (IOException e) {
			throw new AccountException("error.avatarProcess");
		}
		return bytes.toByteArray();
	}

	/** Square `img` scaled to size x size (transparency on white). */
	private static BufferedImage scale(BufferedImage img, int size) {
		BufferedImage out = new BufferedImage(size, size, BufferedImage.TYPE_INT_RGB);
		Graphics2D g = out.createGraphics();
		try {
			g.setRenderingHint(RenderingHints.KEY_INTERPOLATION, RenderingHints.VALUE_INTERPOLATION_BILINEAR);
			g.setRenderingHint(RenderingHints.KEY_RENDERING, RenderingHints.VALUE_RENDER_QUALITY);
			g.setColor(Color.WHITE);
			g.fillRect(0, 0, size, size);
			g.drawImage(img, 0, 0, size, size, null);
		} finally {
			g.dispose();
		}
		return out;
	}

	/** JPEG / PNG / GIF / BMP only, size checked before the pixels are decoded. */
	private static BufferedImage decode(byte[] upload) {
		try (ImageInputStream in = ImageIO.createImageInputStream(new ByteArrayInputStream(upload))) {
			var readers = in == null ? null : ImageIO.getImageReaders(in);
			if (readers == null || !readers.hasNext()) {
				throw new AccountException("error.avatarType");
			}
			ImageReader reader = readers.next();
			try {
				String format = reader.getFormatName().toLowerCase();
				if (!(format.contains("jpeg") || format.equals("png") || format.equals("gif") || format.equals("bmp"))) {
					throw new AccountException("error.avatarType");
				}
				reader.setInput(in, true, true);
				if ((long) reader.getWidth(0) * reader.getHeight(0) > MAX_PIXELS) {
					throw new AccountException("error.avatarBig");
				}
				return reader.read(0);
			} finally {
				reader.dispose();
			}
		} catch (IIOException e) {
			throw new AccountException("error.avatarRead");
		} catch (IOException | RuntimeException e) {
			if (e instanceof AccountException a) {
				throw a;
			}
			throw new AccountException("error.avatarRead");
		}
	}

	private static byte[] randomBytes() {
		byte[] b = new byte[12];
		RANDOM.nextBytes(b);
		return b;
	}
}
