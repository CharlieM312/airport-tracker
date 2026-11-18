import {
	env,
	createExecutionContext,
	waitOnExecutionContext,
	SELF,
} from "cloudflare:test";
import { describe, it, expect } from "vitest";
import worker from "../src";

describe("airport tracker worker", () => {
	it("responds with my message (unit style)", async () => {
		const request = new Request("http://example.com");
		// Create an empty context to pass to `worker.fetch()`.
		const ctx = createExecutionContext();
		const response = await worker.fetch(request, env, ctx);
		// Wait for all `Promise`s passed to `ctx.waitUntil()` to settle before running test assertions
		await waitOnExecutionContext(ctx);
		expect(await response.text()).toMatchInlineSnapshot(`"Airport Tracker API is running. Endpoints: POST /api/login, POST /api/2fa/totp/setup, POST /api/webauthn/*, GET/POST/PATCH/DELETE /api/visits, GET /api/stats, GET/POST /api/airports"`);
	});

	it("responds with my message (integration style)", async () => {
		const response = await SELF.fetch("http://example.com");
		expect(await response.text()).toMatchInlineSnapshot(`"Airport Tracker API is running. Endpoints: POST /api/login, POST /api/2fa/totp/setup, POST /api/webauthn/*, GET/POST/PATCH/DELETE /api/visits, GET /api/stats, GET/POST /api/airports"`);
	});

	it("auto-migrates plaintext passwords to PBKDF2, manages multi-device sessions, enforces brute-force lockout, and authenticates with API keys", async () => {
		// Initialize users table in test D1
		await env.DB.prepare(
			`CREATE TABLE IF NOT EXISTS users (
				id INTEGER PRIMARY KEY AUTOINCREMENT,
				username TEXT NOT NULL UNIQUE,
				password TEXT NOT NULL,
				session_token TEXT,
				totp_secret TEXT,
				totp_pending_secret TEXT,
				webauthn_challenge TEXT,
				role TEXT NOT NULL DEFAULT 'user',
				status TEXT NOT NULL DEFAULT 'approved',
				email TEXT,
				failed_login_attempts INTEGER NOT NULL DEFAULT 0,
				locked_until INTEGER,
				created_at DATETIME DEFAULT CURRENT_TIMESTAMP
			)`
		).run();

		await env.DB.prepare("DELETE FROM users").run();
		await env.DB.prepare(
			"INSERT INTO users (username, password, role, status) VALUES ('CharlieM312', 'legacyPlainPassword', 'admin', 'approved')"
		).run();

		// 1. Login with legacy plaintext password -> should succeed and auto-upgrade password in D1 to PBKDF2
		const loginRes = await SELF.fetch("http://example.com/api/login", {
			method: "POST",
			headers: { "Content-Type": "application/json", "User-Agent": "DesktopBrowser/1.0" },
			body: JSON.stringify({ username: "CharlieM312", password: "legacyPlainPassword" }),
		});
		expect(loginRes.status).toBe(200);
		const loginData = await loginRes.json();
		expect(loginData.success).toBe(true);
		expect(loginData.token).toBeTruthy();

		const upgradedUser = await env.DB.prepare("SELECT password FROM users WHERE username = 'CharlieM312'").first();
		expect(upgradedUser.password.startsWith("pbkdf2$")).toBe(true);

		// 2. Multi-device session: login from a second device and list active sessions
		const secondLoginRes = await SELF.fetch("http://example.com/api/login", {
			method: "POST",
			headers: { "Content-Type": "application/json", "User-Agent": "MobileSafari/1.0" },
			body: JSON.stringify({ username: "CharlieM312", password: "legacyPlainPassword" }),
		});
		expect(secondLoginRes.status).toBe(200);
		const secondLoginData = await secondLoginRes.json();

		// Both session tokens should work simultaneously
		const sessionsRes = await SELF.fetch("http://example.com/api/sessions", {
			headers: { Authorization: `Bearer ${loginData.token}` },
		});
		expect(sessionsRes.status).toBe(200);
		const sessionsData = await sessionsRes.json();
		expect(sessionsData.sessions.length).toBe(2);

		// Revoke all other sessions
		const revokeRes = await SELF.fetch("http://example.com/api/sessions?all_others=true", {
			method: "DELETE",
			headers: { Authorization: `Bearer ${loginData.token}` },
		});
		expect(revokeRes.status).toBe(200);

		// 3. Change password via PATCH /api/user/password
		const pwRes = await SELF.fetch("http://example.com/api/user/password", {
			method: "PATCH",
			headers: {
				"Content-Type": "application/json",
				Authorization: `Bearer ${loginData.token}`,
			},
			body: JSON.stringify({
				current_password: "legacyPlainPassword",
				new_password: "NewSecurePassword123!",
			}),
		});
		expect(pwRes.status).toBe(200);

		// 4. Create & use a Personal Access Token / API key (`atk_...`)
		const keyCreateRes = await SELF.fetch("http://example.com/api/api-keys", {
			method: "POST",
			headers: {
				"Content-Type": "application/json",
				Authorization: `Bearer ${loginData.token}`,
			},
			body: JSON.stringify({ label: "iOS Shortcut", expires_in_days: 30 }),
		});
		expect(keyCreateRes.status).toBe(201);
		const keyCreateData = await keyCreateRes.json();
		expect(keyCreateData.api_key.startsWith("atk_")).toBe(true);

		// Authenticate against a protected endpoint using the new `atk_...` API key
		const statusWithApiKey = await SELF.fetch("http://example.com/api/2fa/status", {
			headers: { Authorization: `Bearer ${keyCreateData.api_key}` },
		});
		expect(statusWithApiKey.status).toBe(200);
		const statusBody = await statusWithApiKey.json();
		expect(statusBody.username).toBe("CharlieM312");
		expect(statusBody.has_password).toBe(true);

		// 5. Brute-force lockout after 5 consecutive failed password attempts
		for (let i = 1; i <= 4; i++) {
			const badRes = await SELF.fetch("http://example.com/api/login", {
				method: "POST",
				headers: { "Content-Type": "application/json" },
				body: JSON.stringify({ username: "CharlieM312", password: "wrong-password" }),
			});
			expect(badRes.status).toBe(401);
		}
		const fifthBadRes = await SELF.fetch("http://example.com/api/login", {
			method: "POST",
			headers: { "Content-Type": "application/json" },
			body: JSON.stringify({ username: "CharlieM312", password: "wrong-password" }),
		});
		expect(fifthBadRes.status).toBe(429);
		const lockBody = await fifthBadRes.json();
		expect(lockBody.locked).toBe(true);
	});
});
