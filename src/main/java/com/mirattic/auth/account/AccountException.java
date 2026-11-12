package com.mirattic.auth.account;

/** A user-facing validation failure: a message key (messages*.properties) and its arguments, shown on the form. */
public class AccountException extends RuntimeException {

	private final transient Object[] args;

	public AccountException(String key, Object... args) {
		super(key);
		this.args = args;
	}

	public String key() {
		return getMessage();
	}

	public Object[] args() {
		return args;
	}
}
