package com.mirattic.auth.admin;

import org.springframework.stereotype.Component;

/** Korean labels for the admin pages (`${@adminLabels.status(...)}`). */
@Component("adminLabels")
public class AdminLabels {

	public String status(String status) {
		return switch (status) {
			case "ACTIVE" -> "정상";
			case "SUSPENDED" -> "정지";
			case "DISABLED" -> "탈퇴 처리 중";
			case "DELETED" -> "탈퇴";
			default -> status;
		};
	}
}
