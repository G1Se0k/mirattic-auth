package com.mirattic.auth.config;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.HexFormat;

/** Per-client key for limits: the IPv4 address, or the /64 of an IPv6 address (one host can rotate a whole /64). */
public final class ClientIp {

	private ClientIp() {
	}

	public static String key(String address) {
		if (address == null || !address.contains(":")) {
			return address;
		}
		try {
			byte[] ip = InetAddress.getByName(address).getAddress();
			return ip.length == 16 ? HexFormat.of().formatHex(ip, 0, 8) + "::/64" : address;
		} catch (UnknownHostException e) {
			return address;
		}
	}
}
