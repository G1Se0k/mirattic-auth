package com.mirattic.auth.account;

import org.springframework.beans.factory.annotation.Value;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import java.time.Duration;
import java.time.Instant;
import java.util.Locale;
import java.util.Set;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

/** Auth's own pages. Passwords are only ever typed here, never into product clients. */
@Controller
class AccountController {

	private final AccountService accounts;
	private final RegisteredClientRepository clients;
	private final Devices devices;
	private final AccountDeletion deletion;
	private final SecurityEvents events;
	private final boolean emailLogin;
	private final SecurityContextLogoutHandler logout = new SecurityContextLogoutHandler();
	private static final Set<String> PROVIDERS = Set.of("kakao", "naver", "google");
	private static final Duration FRESH = Duration.ofMinutes(10);

	private final RequestCache requestCache = new HttpSessionRequestCache();

	AccountController(AccountService accounts, RegisteredClientRepository clients, Devices devices,
			AccountDeletion deletion, SecurityEvents events, @Value("${auth.email-login}") boolean emailLogin) {
		this.events = events;
		this.emailLogin = emailLogin;
		this.accounts = accounts;
		this.clients = clients;
		this.devices = devices;
		this.deletion = deletion;
	}

	@GetMapping("/")
	String home() {
		return "redirect:/account";
	}

	/** Names the product the user came from ("로그인하면 Mirattic Sync로 돌아갑니다"), if any. */
	/** Public: Kakao / Naver review and every product link here. */
	@GetMapping("/privacy")
	String privacy() {
		return "privacy";
	}

	@GetMapping("/login")
	String login(HttpServletRequest request, HttpServletResponse response, Model model) {
		// Back on the login page: an unfinished Kakao / Naver link is abandoned (the next social sign-in is a sign-in).
		HttpSession session = request.getSession(false);
		if (session != null) {
			session.removeAttribute(SocialLogin.LINK);
		}
		SavedRequest saved = requestCache.getRequest(request, response);
		String[] clientId = saved == null ? null : saved.getParameterValues("client_id");
		RegisteredClient client = clientId == null ? null : clients.findByClientId(clientId[0]);
		if (client != null) {
			model.addAttribute("clientName", client.getClientName());
		}
		model.addAttribute("emailLogin", emailLogin);
		return "login";
	}

	@GetMapping("/signup")
	String signupForm() {
		return "signup";
	}

	/** No auto-login: after /login the saved OAuth authorize request (if any) resumes. */
	@PostMapping("/signup")
	String signup(@RequestParam String email, @RequestParam String password, @RequestParam String displayName,
			HttpServletRequest request, Model model) {
		try {
			accounts.signup(email, password, displayName, request.getRemoteAddr());
			return "redirect:/login?signup";
		} catch (AccountException e) {
			model.addAttribute("error", e.getMessage());
			model.addAttribute("email", email);
			model.addAttribute("displayName", displayName);
			return "signup";
		}
	}

	@GetMapping("/password/reset")
	String resetRequestForm() {
		return "reset-request";
	}

	@PostMapping("/password/reset")
	String resetRequest(@RequestParam String email, Model model) {
		accounts.requestPasswordReset(email);
		model.addAttribute("sent", true);
		return "reset-request";
	}

	@GetMapping("/password/reset/confirm")
	String resetConfirmForm(@RequestParam(required = false) String token, Model model) {
		model.addAttribute("token", token);
		return "reset-confirm";
	}

	@PostMapping("/password/reset/confirm")
	String resetConfirm(@RequestParam String token, @RequestParam String password, Model model) {
		try {
			accounts.resetPassword(token, password);
			return "redirect:/login?reset";
		} catch (AccountException e) {
			model.addAttribute("error", e.getMessage());
			model.addAttribute("token", token);
			return "reset-confirm";
		}
	}

	@GetMapping("/account")
	String account(Authentication auth, HttpSession session, Model model) {
		model.addAttribute("account", accounts.find(auth.getName()));
		model.addAttribute("devices", devices.list(auth.getName(), session.getId()));
		model.addAttribute("events", events.recent(auth.getName()));
		return "account";
	}

	@PostMapping("/account/devices/end")
	String endDevice(Authentication auth, @RequestParam String id, HttpSession session) {
		devices.end(auth.getName(), id, session.getId());
		return "redirect:/account?ended#devices";
	}

	/** Starts adding Kakao / Naver: the provider signs the user in, SocialLogin adds that identity to this account. */
	@PostMapping("/account/link/{provider}")
	String link(@PathVariable String provider, Authentication auth, HttpServletRequest request,
			HttpServletResponse response) {
		if (!PROVIDERS.contains(provider)) {
			return "redirect:/account";
		}
		if (stale(auth)) {
			return "redirect:/login?reauth";
		}
		// After the link the user comes back here, not to some older saved request.
		requestCache.removeRequest(request, response);
		request.getSession().setAttribute(SocialLogin.LINK,
				new SocialLogin.Link(auth.getName(), provider, Instant.now()));
		return "redirect:/oauth2/authorization/" + provider;
	}

	@PostMapping("/account/unlink/{provider}")
	String unlink(@PathVariable String provider, Authentication auth, HttpServletRequest request,
			HttpServletResponse response, HttpSession session, Model model) {
		if (!PROVIDERS.contains(provider)) {
			return "redirect:/account";
		}
		if (stale(auth)) {
			return "redirect:/login?reauth";
		}
		try {
			accounts.unlink(auth.getName(), provider.toUpperCase(Locale.ROOT), session.getId());
			// This browser signed in with the method just removed: it is out too.
			if (auth instanceof OAuth2AuthenticationToken social
					&& provider.equals(social.getAuthorizedClientRegistrationId())) {
				logout.logout(request, response, auth);
				return "redirect:/login?unlinked";
			}
			return "redirect:/account?unlinked#methods";
		} catch (AccountException e) {
			return accountWithError(auth, session, model, e);
		}
	}

	/** Deletes the Mirattic account, Sync and Flow data included (AccountDeletion). */
	@PostMapping("/account/delete")
	String delete(Authentication auth, @RequestParam(defaultValue = "false") boolean confirm, HttpServletRequest request,
			HttpServletResponse response, Model model) {
		if (!confirm) {
			return accountWithError(auth, request.getSession(), model, new AccountException("탈퇴 확인에 체크해주세요."));
		}
		if (stale(auth)) {
			return "redirect:/login?reauth";
		}
		try {
			deletion.delete(auth.getName(), request.getSession().getId());
		} catch (AccountException e) {
			return accountWithError(auth, request.getSession(), model, e);
		}
		logout.logout(request, response, auth);
		return "redirect:/login?deleted";
	}

	/** Changing how the account signs in, or deleting it, needs a sign-in in the last 10 minutes. */
	private static boolean stale(Authentication auth) {
		return AccountService.signInTime(auth).isBefore(Instant.now().minus(FRESH));
	}

	@PostMapping("/account/name")
	String changeName(Authentication auth, @RequestParam String displayName, HttpSession session, Model model) {
		try {
			accounts.changeDisplayName(auth.getName(), displayName);
			return "redirect:/account?saved";
		} catch (AccountException e) {
			return accountWithError(auth, session, model, e);
		}
	}

	@PostMapping("/account/password")
	String changePassword(Authentication auth, @RequestParam String currentPassword, @RequestParam String password,
			HttpSession session, Model model) {
		try {
			accounts.changePassword(auth.getName(), currentPassword, password, session.getId());
			return "redirect:/account?password";
		} catch (AccountException e) {
			return accountWithError(auth, session, model, e);
		}
	}

	private String accountWithError(Authentication auth, HttpSession session, Model model, AccountException e) {
		model.addAttribute("error", e.getMessage());
		return account(auth, session, model);
	}
}
