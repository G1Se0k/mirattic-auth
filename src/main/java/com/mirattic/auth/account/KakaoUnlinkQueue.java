package com.mirattic.auth.account;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.List;
import java.util.zip.CRC32;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

/**
 * Kakao unlinks waiting to be applied, in a small journal file on the persistent volume (next to the signing key).
 * The webhook only appends a line (no database), so it answers within Kakao's 3 s and nothing is lost if the
 * database is down or Auth restarts. One line: `<kakao user id>\t<referrer_type>\t<crc32 of the two>`; a line cut
 * short by a crash fails the checksum and is dropped, never read as a different (shorter) user id.
 * <p>
 * The worker never rewrites the journal: it renames it to `<journal>.processing` (atomic, instant — the webhook's
 * lock is held only that long), applies the lines outside the lock, appends the failures back to the journal, then
 * deletes the processing file. A crash in between leaves the processing file, which the next run applies first
 * (applying an unlink twice is harmless).
 */
@Component
public class KakaoUnlinkQueue {

	private static final Logger log = LoggerFactory.getLogger(KakaoUnlinkQueue.class);

	private final Path file;
	private final Path processing;
	private final AccountService accounts;

	KakaoUnlinkQueue(@Value("${auth.kakao.unlink-journal:./.local/kakao-unlinks.log}") String path,
			AccountService accounts) {
		this.file = Path.of(path).toAbsolutePath();
		this.processing = file.resolveSibling(file.getFileName() + ".processing");
		this.accounts = accounts;
	}

	/** Durably records one unlink: fully written and forced to disk before returning. False: not a Kakao user id. */
	boolean add(String kakaoUserId, String referrer) {
		// Kakao member numbers are numeric. Checked on the raw value, untouched: trimming or stripping first could
		// turn "\n42" or "42\n99" into a valid-looking (and different) number.
		String id = kakaoUserId == null ? "" : kakaoUserId;
		if (!id.matches("[0-9]{1,20}")) {
			return false;
		}
		// referrer_type is Kakao's enum (ACCOUNT_DELETE, UNLINK_FROM_APPS, ...): ASCII only, so a record is ASCII and
		// a crash can't cut a multi-byte character in half.
		String kind = referrer != null && referrer.matches("[A-Z_]{1,40}") ? referrer : "UNKNOWN";
		appendDurably(List.of(record(id, kind)));
		return true;
	}

	/** Applies what is waiting: sign the account out everywhere. Failures go back to the journal. */
	@Scheduled(fixedDelay = 5_000)
	public void process() {
		try {
			synchronized (this) {
				if (!Files.exists(processing) && Files.exists(file)) {
					Files.move(file, processing, StandardCopyOption.ATOMIC_MOVE);
					syncDirectory();
				}
			}
			if (!Files.exists(processing)) {
				return;
			}
			List<String> failed = new ArrayList<>();
			// Decoded leniently: a damaged byte becomes U+FFFD, and that line then fails its checksum and is dropped
			// instead of stopping the whole batch.
			for (String line : new String(Files.readAllBytes(processing), StandardCharsets.UTF_8).split("\n")) {
				if (line.isBlank()) {
					continue;
				}
				String[] parts = line.split("\t");
				if (parts.length != 3 || !record(parts[0], parts[1]).equals(line)) {
					log.error("Kakao unlink journal: dropped an incomplete or corrupt record");
					continue;
				}
				try {
					accounts.userOfIdentity("KAKAO", parts[0]).ifPresent(uid -> {
						accounts.endSessions(uid, null);
						log.info("Kakao unlink ({}): signed out user {} everywhere", parts.length > 1 ? parts[1] : "", uid);
					});
				} catch (RuntimeException e) {
					log.error("Kakao unlink for Kakao user {} failed; kept for the next run", parts[0], e);
					failed.add(line);
				}
			}
			if (!failed.isEmpty()) {
				appendDurably(failed); // before deleting the processing file: never lost, at worst applied twice
			}
			Files.delete(processing);
			syncDirectory();
		} catch (IOException | UncheckedIOException e) {
			log.error("Kakao unlink journal not processed; will retry", e);
		}
	}

	synchronized int pending() {
		try {
			int n = 0;
			for (Path p : List.of(file, processing)) {
				if (Files.exists(p)) {
					n += (int) Files.readAllLines(p, StandardCharsets.UTF_8).stream().filter(l -> !l.isBlank()).count();
				}
			}
			return n;
		} catch (IOException e) {
			throw new UncheckedIOException(e);
		}
	}

	private synchronized void appendDurably(List<String> lines) {
		try {
			Files.createDirectories(file.getParent());
			// READ + WRITE, then write at the end (Java refuses READ + APPEND; appends are serialized by this lock).
			try (FileChannel out = FileChannel.open(file, StandardOpenOption.CREATE, StandardOpenOption.READ,
					StandardOpenOption.WRITE)) {
				// A crash mid-append can leave a line without its newline: start on a fresh line so the fragment
				// stays alone (and fails its checksum) instead of merging with this record.
				String prefix = "";
				if (out.size() > 0) {
					ByteBuffer last = ByteBuffer.allocate(1);
					out.read(last, out.size() - 1);
					prefix = last.get(0) == '\n' ? "" : "\n";
				}
				ByteBuffer buffer = StandardCharsets.UTF_8.encode(prefix + String.join("\n", lines) + "\n");
				out.position(out.size());
				while (buffer.hasRemaining()) { // a write may be partial
					out.write(buffer);
				}
				out.force(true);
			}
			// Every time, not only when the file is new: after a failed sync the entry may still be unconfirmed.
			// Unlinks are rare, so the extra fsync costs nothing.
			syncDirectory(true);
		} catch (IOException e) {
			throw new UncheckedIOException(e);
		}
	}

	private void syncDirectory() throws IOException {
		syncDirectory(false);
	}

	/**
	 * Makes renames / creations durable (fsync of the directory). `required`: fail if it can't be done (append path,
	 * before the webhook answers 200); otherwise log (the worker only moves records it already has).
	 */
	private void syncDirectory(boolean required) throws IOException {
		try (FileChannel dir = FileChannel.open(file.getParent(), StandardOpenOption.READ)) {
			dir.force(true);
		} catch (IOException e) {
			if (required) {
				throw e;
			}
			log.warn("directory fsync failed", e);
		}
	}

	private static String record(String kakaoUserId, String referrer) {
		CRC32 crc = new CRC32();
		crc.update((kakaoUserId + "\t" + referrer).getBytes(StandardCharsets.UTF_8));
		return kakaoUserId + "\t" + referrer + "\t" + Long.toHexString(crc.getValue());
	}

}
