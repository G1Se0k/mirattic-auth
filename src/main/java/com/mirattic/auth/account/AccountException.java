package com.mirattic.auth.account;

/** A user-facing validation failure; the message is shown on the form as is. */
public class AccountException extends RuntimeException {

	public AccountException(String message) {
		super(message);
	}
}
