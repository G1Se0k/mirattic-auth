package com.mirattic.auth.admin;

import com.mirattic.auth.account.ProductOrders;
import java.time.Duration;
import java.util.List;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.client.SimpleClientHttpRequestFactory;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestClientException;

/**
 * Sync / Flow data for the admin console, read over a back-channel (docs/admin.md "Product reads"): GET {url}/stats and
 * GET {url}/users/{uid} (Sync also {url}/reports, {url}/feedback) with a `purpose: admin_read` order. Each product decides what it shows, as label/value facts
 * and small tables; Auth only renders them. Read-only. A product that doesn't answer shows as an error, not a failure.
 */
@Component
class ProductAdmin {

	static final String PURPOSE = "admin_read";

	record Table(String title, List<String> columns, List<List<String>> rows) {
	}

	/** What a product sends. `more`: a paged list has a next page. */
	record Body(List<List<String>> facts, List<Table> tables, Boolean more) {
	}

	/** `error` set: nothing else is. */
	record Report(String name, List<List<String>> facts, List<Table> tables, boolean more, String error) {
	}

	private record Product(String clientId, String name, String url) {
	}

	private static final Logger log = LoggerFactory.getLogger(ProductAdmin.class);

	private final List<Product> products;
	private final ProductOrders orders;
	private final RestClient http;

	ProductAdmin(@Value("${auth.admin.sync-url}") String syncUrl, @Value("${auth.admin.flow-url}") String flowUrl,
			ProductOrders orders) {
		this.products = List.of(new Product("mirattic-sync", "Mirattic Sync", syncUrl),
				new Product("mirattic-flow", "Mirattic Flow", flowUrl));
		this.orders = orders;
		SimpleClientHttpRequestFactory timeouts = new SimpleClientHttpRequestFactory();
		timeouts.setConnectTimeout(Duration.ofSeconds(3));
		timeouts.setReadTimeout(Duration.ofSeconds(5));
		this.http = RestClient.builder().requestFactory(timeouts).build();
	}

	/** `adminUid` is the order's `sub`: who asked. */
	List<Report> stats(String adminUid) {
		return products.stream().map(p -> read(p, "/stats", adminUid)).toList();
	}

	List<Report> user(String uid, String adminUid) {
		return products.stream().map(p -> read(p, "/users/" + uid, adminUid)).toList();
	}

	/** Sync's full lists (`reports`, `feedback`), one page. */
	Report syncList(String list, int page, String adminUid) {
		return read(products.getFirst(), "/" + list + "?page=" + page, adminUid);
	}

	private Report read(Product p, String path, String adminUid) {
		try {
			Body body = http.get().uri(p.url() + path)
					.headers(h -> h.setBearerAuth(orders.sign(p.clientId(), adminUid, PURPOSE)))
					.retrieve().body(Body.class);
			if (body == null) {
				throw new RestClientException("empty");
			}
			return new Report(p.name(), body.facts() == null ? List.of() : body.facts(),
					body.tables() == null ? List.of() : body.tables(), Boolean.TRUE.equals(body.more()), null);
		} catch (RestClientException e) {
			log.warn("{} admin read failed: {}", p.clientId(), e.getClass().getSimpleName());
			return new Report(p.name(), List.of(), List.of(), false, "응답을 받지 못했습니다.");
		}
	}
}
