package com.mirattic.auth.account;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Optional;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.dao.DataAccessResourceFailureException;

/** The webhook only records the unlink; the journal survives failures and restarts until the sign-out goes through. */
class KakaoUnlinkControllerTest {

	@TempDir
	Path dir;

	@Test
	void theWebhookAnswersWithoutTheDatabaseAndTheWorkSurvivesFailuresAndRestarts() throws Exception {
		AccountService accounts = mock(AccountService.class);
		when(accounts.userOfIdentity("KAKAO", "42")).thenReturn(Optional.of("uid-1"));
		doThrow(new DataAccessResourceFailureException("db down")).doNothing().when(accounts).endSessions("uid-1", null);
		Path journal = dir.resolve("unlinks.log");
		KakaoUnlinkQueue queue = new KakaoUnlinkQueue(journal.toString(), accounts);
		KakaoUnlinkController controller = new KakaoUnlinkController(queue, "admin");

		assertThat(controller.unlink("KakaoAK admin", "42", "UNLINK_FROM_APPS").getStatusCode().value()).isEqualTo(200);
		verifyNoInteractions(accounts); // nothing touched the database on the request
		assertThat(Files.readString(journal)).startsWith("42\tUNLINK_FROM_APPS\t").endsWith("\n");

		queue.process(); // database down: kept
		assertThat(queue.pending()).isOne();

		// Auth restarts: a new queue on the same file picks it up and succeeds.
		KakaoUnlinkQueue restarted = new KakaoUnlinkQueue(journal.toString(), accounts);
		restarted.process();
		assertThat(restarted.pending()).isZero();
		verify(accounts, times(2)).endSessions("uid-1", null);
	}

	@Test
	void aCrashWhileProcessingLeavesTheBatchForTheNextRun() throws Exception {
		AccountService accounts = mock(AccountService.class);
		when(accounts.userOfIdentity("KAKAO", "7")).thenReturn(Optional.of("uid-7"));
		Path journal = dir.resolve("unlinks.log");
		// As if Auth died after taking the batch but before finishing it; a new unlink arrived meanwhile.
		KakaoUnlinkQueue writer = new KakaoUnlinkQueue(dir.resolve("other.log").toString(), accounts);
		writer.add("7", "ACCOUNT_DELETE");
		Files.move(dir.resolve("other.log"), dir.resolve("unlinks.log.processing"));
		KakaoUnlinkQueue queue = new KakaoUnlinkQueue(journal.toString(), accounts);
		queue.add("8", "UNLINK_FROM_APPS");
		assertThat(queue.pending()).isEqualTo(2);

		queue.process(); // the leftover batch first
		verify(accounts).endSessions("uid-7", null);
		queue.process(); // then the new one
		assertThat(queue.pending()).isZero();
	}

	@Test
	void wrongOrMissingKeyIsRefusedAndMissingConfigIsUnavailable() {
		KakaoUnlinkQueue queue = new KakaoUnlinkQueue(dir.resolve("q.log").toString(), mock(AccountService.class));
		assertThat(new KakaoUnlinkController(queue, "admin").unlink("KakaoAK nope", "42", null).getStatusCode().value())
				.isEqualTo(401);
		assertThat(new KakaoUnlinkController(queue, "").unlink("KakaoAK admin", "42", null).getStatusCode().value())
				.isEqualTo(503);
		assertThat(queue.pending()).isZero();
	}

	@Test
	void onlyKakaoMemberNumbersAreRecorded() {
		KakaoUnlinkQueue queue = new KakaoUnlinkQueue(dir.resolve("q.log").toString(), mock(AccountService.class));
		assertThat(queue.add("42\n99", "X")).isFalse();
		assertThat(queue.add("abc", "X")).isFalse();
		assertThat(queue.add("\n42", "X")).isFalse();
		assertThat(queue.add(" 42", "X")).isFalse();
		assertThat(queue.add("42", "X\tY\nZ")).isTrue(); // an odd referrer_type is recorded as UNKNOWN, still one line
		assertThat(queue.pending()).isOne();
	}

	@Test
	void aDamagedByteDoesNotBlockTheOtherRecords() throws Exception {
		AccountService accounts = mock(AccountService.class);
		when(accounts.userOfIdentity("KAKAO", "43")).thenReturn(Optional.of("uid-43"));
		Path journal = dir.resolve("unlinks.log");
		Files.write(journal, new byte[] {'4', '2', '\t', (byte) 0xE2, (byte) 0x82, '\n'}); // cut mid-character
		KakaoUnlinkQueue queue = new KakaoUnlinkQueue(journal.toString(), accounts);
		queue.add("43", "UNLINK_FROM_APPS");
		queue.process();
		verify(accounts).endSessions("uid-43", null);
		assertThat(queue.pending()).isZero();
	}

	@Test
	void aRecordCutShortByACrashIsDroppedAndNeverMergesWithTheNextOne() throws Exception {
		AccountService accounts = mock(AccountService.class);
		when(accounts.userOfIdentity("KAKAO", "43")).thenReturn(Optional.of("uid-43"));
		Path journal = dir.resolve("unlinks.log");
		Files.writeString(journal, "4"); // "42\t...\t<crc>\n" interrupted after one byte
		KakaoUnlinkQueue queue = new KakaoUnlinkQueue(journal.toString(), accounts);
		queue.add("43", "UNLINK_FROM_APPS");

		queue.process();
		verify(accounts, times(1)).userOfIdentity("KAKAO", "43");
		verify(accounts, times(0)).userOfIdentity("KAKAO", "4"); // the fragment is not read as user 4
		verify(accounts).endSessions("uid-43", null);
		assertThat(queue.pending()).isZero();
	}
}
