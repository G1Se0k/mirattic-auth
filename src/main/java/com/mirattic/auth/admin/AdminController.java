package com.mirattic.auth.admin;

import com.mirattic.auth.account.AccountService;
import com.mirattic.auth.account.Devices;
import com.mirattic.auth.account.SecurityEvents;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.server.ResponseStatusException;

/**
 * Admin console (docs/admin.md): accounts, their sign-ins and Sync / Flow data, suspension. Only ADMIN_UIDS get here
 * (SecurityConfig). Reads show no secrets: no password hashes, tokens or IPs. Every change is logged with who did it.
 */
@Controller
@RequestMapping("/admin")
class AdminController {

	record UserRow(String id, String displayName, String email, String providers, String status, ZonedDateTime createdAt,
			ZonedDateTime lastAppUseAt) {
	}

	record Identity(String provider, String email, ZonedDateTime linkedAt) {
	}

	/** Distinct users whose app login refreshed in the last day / week / 30 days. */
	record Usage(String product, long day, long week, long month) {
	}

	private static final Logger log = LoggerFactory.getLogger(AdminController.class);
	private static final ZoneId SEOUL = ZoneId.of("Asia/Seoul");
	private static final Pattern UUID = Pattern.compile("[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}");
	private static final int PAGE = 50;
	/** Changes need a sign-in in the last 10 minutes, as the account page's. */
	private static final Duration FRESH = Duration.ofMinutes(10);
	private static final String LAST_APP_USE = "(SELECT MAX(a.refresh_token_issued_at) FROM oauth2_authorization a "
			+ "WHERE a.principal_name = u.id)";

	private final JdbcTemplate jdbc;
	private final AccountService accounts;
	private final Devices devices;
	private final SecurityEvents events;
	private final RegisteredClientRepository clients;
	private final ProductAdmin products;

	AdminController(JdbcTemplate jdbc, AccountService accounts, Devices devices, SecurityEvents events,
			RegisteredClientRepository clients, ProductAdmin products) {
		this.jdbc = jdbc;
		this.accounts = accounts;
		this.devices = devices;
		this.events = events;
		this.clients = clients;
		this.products = products;
	}

	/** Dashboard and user search: by UID, email (any identity's) or name. */
	@GetMapping
	String index(@RequestParam(defaultValue = "") String q, @RequestParam(defaultValue = "0") int page,
			Authentication auth, Model model) {
		String query = q.strip();
		int offset = Math.max(page, 0) * PAGE;
		String like = "%" + query.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%";
		List<UserRow> users = jdbc.query("""
				SELECT u.id, u.display_name, (%s),
				  (SELECT GROUP_CONCAT(i.provider ORDER BY i.created_at) FROM user_identities i WHERE i.user_id = u.id),
				  u.status, u.created_at, %s
				FROM users u
				WHERE ? = '' OR u.id = ? OR u.display_name LIKE ?
				   OR EXISTS (SELECT 1 FROM user_identities i WHERE i.user_id = u.id AND i.email LIKE ?)
				ORDER BY u.created_at DESC, u.id LIMIT ? OFFSET ?
				""".formatted(AccountService.CONTACT_EMAIL, LAST_APP_USE), (rs, n) -> new UserRow(rs.getString(1),
				rs.getString(2), rs.getString(3), rs.getString(4), rs.getString(5), seoul(rs, 6), seoul(rs, 7)),
				query, query, like, like, PAGE + 1, offset);
		model.addAttribute("q", query);
		model.addAttribute("page", Math.max(page, 0));
		model.addAttribute("more", users.size() > PAGE);
		model.addAttribute("users", users.subList(0, Math.min(users.size(), PAGE)));
		if (query.isEmpty() && page <= 0) {
			dashboard(auth, model);
		}
		return "admin";
	}

	private void dashboard(Authentication auth, Model model) {
		Map<String, Long> statuses = new LinkedHashMap<>();
		for (String s : List.of("ACTIVE", "SUSPENDED", "DISABLED", "DELETED")) {
			statuses.put(s, 0L);
		}
		jdbc.query("SELECT status, COUNT(*) FROM users GROUP BY status",
				rs -> { statuses.put(rs.getString(1), rs.getLong(2)); });
		model.addAttribute("statuses", statuses);
		// Days in Seoul time; DB times are UTC.
		List<Map<String, Object>> signups = jdbc.queryForList("""
				SELECT DATE(created_at + INTERVAL 9 HOUR) AS day, COUNT(*) AS n FROM users
				WHERE created_at >= NOW(6) - INTERVAL 14 DAY GROUP BY day ORDER BY day DESC
				""");
		model.addAttribute("signups", signups);
		model.addAttribute("signupMax", signups.stream().mapToLong(r -> ((Number) r.get("n")).longValue()).max()
				.orElse(1));
		// ponytail: "app use" = the app refreshed its login (every ≤15 min while open); logins ended or expired over a
		// day ago are gone (ExpiredDataCleanup), so older use is undercounted. Product-side activity would be exact.
		List<Usage> usage = new ArrayList<>();
		jdbc.query("""
				SELECT registered_client_id,
				  COUNT(DISTINCT CASE WHEN refresh_token_issued_at >= NOW() - INTERVAL 1 DAY THEN principal_name END),
				  COUNT(DISTINCT CASE WHEN refresh_token_issued_at >= NOW() - INTERVAL 7 DAY THEN principal_name END),
				  COUNT(DISTINCT CASE WHEN refresh_token_issued_at >= NOW() - INTERVAL 30 DAY THEN principal_name END)
				FROM oauth2_authorization WHERE refresh_token_issued_at IS NOT NULL GROUP BY registered_client_id
				ORDER BY registered_client_id
				""", rs -> {
			RegisteredClient client = clients.findById(rs.getString(1));
			usage.add(new Usage(client == null ? rs.getString(1) : client.getClientName(), rs.getLong(2), rs.getLong(3),
					rs.getLong(4)));
		});
		model.addAttribute("usage", usage);
		model.addAttribute("products", products.stats(auth.getName()));
	}

	@GetMapping("/users/{id}")
	String user(@PathVariable String id, Authentication auth, Model model) {
		List<UserRow> found = jdbc.query("""
				SELECT u.id, u.display_name, (%s), NULL, u.status, u.created_at, %s FROM users u WHERE u.id = ?
				""".formatted(AccountService.CONTACT_EMAIL, LAST_APP_USE), (rs, n) -> new UserRow(rs.getString(1),
				rs.getString(2), rs.getString(3), null, rs.getString(5), seoul(rs, 6), seoul(rs, 7)), uuid(id));
		if (found.isEmpty()) {
			throw new ResponseStatusException(HttpStatus.NOT_FOUND);
		}
		model.addAttribute("user", found.getFirst());
		model.addAttribute("self", id.equals(auth.getName()));
		model.addAttribute("identities", jdbc.query("SELECT provider, email, created_at FROM user_identities "
				+ "WHERE user_id = ? ORDER BY created_at", (rs, n) -> new Identity(rs.getString(1), rs.getString(2),
				seoul(rs, 3)), id));
		model.addAttribute("devices", devices.list(id, null));
		model.addAttribute("events", events.recent(id, 30));
		model.addAttribute("products", products.user(id, auth.getName()));
		return "admin-user";
	}

	@PostMapping("/users/{id}/suspend")
	String suspend(@PathVariable String id, Authentication auth) {
		if (stale(auth)) {
			return "redirect:/login?reauth";
		}
		if (uuid(id).equals(auth.getName())) {
			return "redirect:/admin/users/" + id + "?self";
		}
		boolean done = accounts.suspend(id);
		log.info("Admin {} suspended {}: {}", auth.getName(), id, done ? "done" : "not active");
		return "redirect:/admin/users/" + id + (done ? "?suspended" : "?unchanged");
	}

	@PostMapping("/users/{id}/resume")
	String resume(@PathVariable String id, Authentication auth) {
		if (stale(auth)) {
			return "redirect:/login?reauth";
		}
		boolean done = accounts.resume(uuid(id));
		log.info("Admin {} resumed {}: {}", auth.getName(), id, done ? "done" : "not suspended");
		return "redirect:/admin/users/" + id + (done ? "?resumed" : "?unchanged");
	}

	/** Every browser session and app login of the user ends (app access tokens lapse within 15 min). */
	@PostMapping("/users/{id}/sign-out")
	String signOut(@PathVariable String id, Authentication auth) {
		if (stale(auth)) {
			return "redirect:/login?reauth";
		}
		if (uuid(id).equals(auth.getName())) {
			return "redirect:/admin/users/" + id + "?self";
		}
		accounts.endSessions(id, null);
		events.record(id, SecurityEvents.Type.ADMIN_SIGNED_OUT, null);
		log.info("Admin {} signed out {}", auth.getName(), id);
		return "redirect:/admin/users/" + id + "?signedOut";
	}

	private static boolean stale(Authentication auth) {
		return AccountService.signInTime(auth).isBefore(Instant.now().minus(FRESH));
	}

	/** Path ids are UUIDs (also: they go into product URLs). */
	private static String uuid(String id) {
		if (!UUID.matcher(id).matches()) {
			throw new ResponseStatusException(HttpStatus.NOT_FOUND);
		}
		return id;
	}

	private static ZonedDateTime seoul(ResultSet rs, int column) throws SQLException {
		Timestamp t = rs.getTimestamp(column);
		return t == null ? null : t.toInstant().atZone(SEOUL);
	}
}
