package com.mirattic.auth.account;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

/** Auth's own pages. Passwords are only ever typed here, never into product clients. */
@Controller
class AccountController {

	private final AccountService accounts;
	private final RegisteredClientRepository clients;
	private final RequestCache requestCache = new HttpSessionRequestCache();

	AccountController(AccountService accounts, RegisteredClientRepository clients) {
		this.accounts = accounts;
		this.clients = clients;
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
		SavedRequest saved = requestCache.getRequest(request, response);
		String[] clientId = saved == null ? null : saved.getParameterValues("client_id");
		RegisteredClient client = clientId == null ? null : clients.findByClientId(clientId[0]);
		if (client != null) {
			model.addAttribute("clientName", client.getClientName());
		}
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
	String account(Authentication auth, Model model) {
		model.addAttribute("account", accounts.find(auth.getName()));
		return "account";
	}

	@PostMapping("/account/name")
	String changeName(Authentication auth, @RequestParam String displayName, Model model) {
		try {
			accounts.changeDisplayName(auth.getName(), displayName);
			return "redirect:/account?saved";
		} catch (AccountException e) {
			return accountWithError(auth, model, e);
		}
	}

	@PostMapping("/account/password")
	String changePassword(Authentication auth, @RequestParam String currentPassword, @RequestParam String password,
			HttpSession session, Model model) {
		try {
			accounts.changePassword(auth.getName(), currentPassword, password, session.getId());
			return "redirect:/account?password";
		} catch (AccountException e) {
			return accountWithError(auth, model, e);
		}
	}

	private String accountWithError(Authentication auth, Model model, AccountException e) {
		model.addAttribute("error", e.getMessage());
		return account(auth, model);
	}
}
