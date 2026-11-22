import {
	env,
	createExecutionContext,
	waitOnExecutionContext,
	SELF,
} from "cloudflare:test";
import { describe, it, expect, beforeEach } from "vitest";
import worker from "../src";

const BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

function base32ToBytes(base32) {
	const cleaned = String(base32 || "")
		.toUpperCase()
		.replace(/=+$/, "")
		.replace(/\s+/g, "");
	let bits = 0;
	let value = 0;
	const bytes = [];
	for (const char of cleaned) {
		const idx = BASE32_ALPHABET.indexOf(char);
		if (idx === -1) continue;
		value = (value << 5) | idx;
		bits += 5;
		if (bits >= 8) {
			bytes.push((value >>> (bits - 8)) & 0xff);
			bits -= 8;
		}
	}
	return new Uint8Array(bytes);
}

async function generateTotpCodeForTest(secretBase32) {
	const counter = Math.floor(Date.now() / 30000);
	const keyBytes = base32ToBytes(secretBase32);
	const counterBytes = new ArrayBuffer(8);
	new DataView(counterBytes).setUint32(4, counter, false);
	const key = await crypto.subtle.importKey(
		"raw",
		keyBytes,
		{ name: "HMAC", hash: "SHA-1" },
		false,
		["sign"]
	);
	const hmac = new Uint8Array(await crypto.subtle.sign("HMAC", key, counterBytes));
	const offset = hmac[hmac.length - 1] & 0x0f;
	const binary =
		((hmac[offset] & 0x7f) << 24) |
		((hmac[offset + 1] & 0xff) << 16) |
		((hmac[offset + 2] & 0xff) << 8) |
		(hmac[offset + 3] & 0xff);
	return String(binary % 1_000_000).padStart(6, "0");
}

function bytesToBase64Url(bytes) {
	let binary = "";
	for (const b of bytes) {
		binary += String.fromCharCode(b);
	}
	return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function p1363ToDerSignature(p1363Bytes) {
	const r = p1363Bytes.slice(0, 32);
	const s = p1363Bytes.slice(32, 64);
	const encodeInt = (buf) => {
		let i = 0;
		while (i < buf.length - 1 && buf[i] === 0) i++;
		const sliced = buf.slice(i);
		if (sliced[0] & 0x80) {
			const padded = new Uint8Array(sliced.length + 1);
			padded[0] = 0;
			padded.set(sliced, 1);
			return padded;
		}
		return sliced;
	};
	const rEnc = encodeInt(r);
	const sEnc = encodeInt(s);
	const totalLen = 2 + rEnc.length + 2 + sEnc.length;
	const der = new Uint8Array(2 + totalLen);
	let offset = 0;
	der[offset++] = 0x30;
	der[offset++] = totalLen;
	der[offset++] = 0x02;
	der[offset++] = rEnc.length;
	der.set(rEnc, offset);
	offset += rEnc.length;
	der[offset++] = 0x02;
	der[offset++] = sEnc.length;
	der.set(sEnc, offset);
	return der;
}

function createFakeJwt(claims) {
	const header = bytesToBase64Url(
		new TextEncoder().encode(JSON.stringify({ alg: "RS256", typ: "JWT" }))
	);
	const payload = bytesToBase64Url(
		new TextEncoder().encode(JSON.stringify(claims))
	);
	return `${header}.${payload}.signature`;
}

async function initDatabase() {
	await env.DB.batch([
		env.DB.prepare(
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
		),
		env.DB.prepare(
			`CREATE TABLE IF NOT EXISTS airports (
				iata_code TEXT PRIMARY KEY,
				name TEXT NOT NULL,
				city TEXT,
				country TEXT,
				latitude REAL NOT NULL,
				longitude REAL NOT NULL
			)`
		),
		env.DB.prepare(
			`CREATE TABLE IF NOT EXISTS airport_visits (
				id INTEGER PRIMARY KEY AUTOINCREMENT,
				iata_code TEXT NOT NULL,
				airport_name TEXT,
				visit_date TEXT NOT NULL,
				username TEXT NOT NULL,
				notes TEXT,
				origin_iata TEXT,
				destination_iata TEXT,
				flight_number TEXT,
				distance_km REAL,
				created_at DATETIME DEFAULT CURRENT_TIMESTAMP
			)`
		),
	]);
}

describe("airport tracker worker", () => {
	beforeEach(async () => {
		await initDatabase();
	});

	it("responds with my message (unit style)", async () => {
		const request = new Request("http://example.com");
		const ctx = createExecutionContext();
		const response = await worker.fetch(request, env, ctx);
		await waitOnExecutionContext(ctx);
		expect(await response.text()).toMatchInlineSnapshot(`"Airport Tracker API is running. Endpoints: POST /api/login, POST /api/2fa/totp/setup, POST /api/webauthn/*, GET/POST/PATCH/DELETE /api/visits, GET /api/stats, GET/POST /api/airports"`);
	});

	it("responds with my message (integration style) and handles CORS OPTIONS preflight", async () => {
		const response = await SELF.fetch("http://example.com");
		expect(await response.text()).toMatchInlineSnapshot(`"Airport Tracker API is running. Endpoints: POST /api/login, POST /api/2fa/totp/setup, POST /api/webauthn/*, GET/POST/PATCH/DELETE /api/visits, GET /api/stats, GET/POST /api/airports"`);

		const optionsRes = await SELF.fetch("http://example.com/api/visits", {
			method: "OPTIONS",
		});
		expect(optionsRes.status).toBe(204);
		expect(optionsRes.headers.get("Access-Control-Allow-Origin")).toBe("*");
	});

	it("auto-migrates plaintext passwords to PBKDF2, manages multi-device sessions, enforces brute-force lockout, and authenticates with API keys", async () => {
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

		const sessionsRes = await SELF.fetch("http://example.com/api/sessions", {
			headers: { Authorization: `Bearer ${loginData.token}` },
		});
		expect(sessionsRes.status).toBe(200);
		const sessionsData = await sessionsRes.json();
		expect(sessionsData.sessions.length).toBe(2);

		// Revoke specific session by ID, then revoke all_others
		const otherSession = sessionsData.sessions.find((s) => !s.is_current);
		if (otherSession) {
			const singleRevoke = await SELF.fetch(`http://example.com/api/sessions/${otherSession.id}`, {
				method: "DELETE",
				headers: { Authorization: `Bearer ${loginData.token}` },
			});
			expect(singleRevoke.status).toBe(200);
		}

		const revokeRes = await SELF.fetch("http://example.com/api/sessions?all_others=true", {
			method: "DELETE",
			headers: { Authorization: `Bearer ${loginData.token}` },
		});
		expect(revokeRes.status).toBe(200);

		// 3. Change password via PATCH /api/user/password (including error cases)
		const shortPwRes = await SELF.fetch("http://example.com/api/user/password", {
			method: "PATCH",
			headers: { "Content-Type": "application/json", Authorization: `Bearer ${loginData.token}` },
			body: JSON.stringify({ current_password: "legacyPlainPassword", new_password: "short" }),
		});
		expect(shortPwRes.status).toBe(400);

		const wrongCurrentPwRes = await SELF.fetch("http://example.com/api/user/password", {
			method: "PATCH",
			headers: { "Content-Type": "application/json", Authorization: `Bearer ${loginData.token}` },
			body: JSON.stringify({ current_password: "wrongPassword", new_password: "NewSecurePassword123!" }),
		});
		expect(wrongCurrentPwRes.status).toBe(401);

		const pwRes = await SELF.fetch("http://example.com/api/user/password", {
			method: "PATCH",
			headers: {
				"Content-Type": "application/json",
				Authorization: `Bearer ${loginData.token}`,
			},
			body: JSON.stringify({
				current_password: "legacyPlainPassword",
				new_password: "NewSecurePassword123!",
				revoke_other_sessions: true,
			}),
		});
		expect(pwRes.status).toBe(200);

		// 4. Create, list, use & revoke a Personal Access Token / API key (`atk_...`)
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

		const listKeysRes = await SELF.fetch("http://example.com/api/api-keys", {
			headers: { Authorization: `Bearer ${loginData.token}` },
		});
		expect(listKeysRes.status).toBe(200);
		const listKeysData = await listKeysRes.json();
		expect(listKeysData.api_keys.length).toBe(1);

		const statusWithApiKey = await SELF.fetch("http://example.com/api/2fa/status", {
			headers: { Authorization: `Bearer ${keyCreateData.api_key}` },
		});
		expect(statusWithApiKey.status).toBe(200);
		const statusBody = await statusWithApiKey.json();
		expect(statusBody.username).toBe("CharlieM312");
		expect(statusBody.has_password).toBe(true);

		// Delete API key
		const delKeyRes = await SELF.fetch(`http://example.com/api/api-keys/${listKeysData.api_keys[0].id}`, {
			method: "DELETE",
			headers: { Authorization: `Bearer ${loginData.token}` },
		});
		expect(delKeyRes.status).toBe(200);

		// Revoked API key should now return 401
		const revokedKeyRes = await SELF.fetch("http://example.com/api/2fa/status", {
			headers: { Authorization: `Bearer ${keyCreateData.api_key}` },
		});
		expect(revokedKeyRes.status).toBe(401);

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

		// Locked account even rejects the right password while locked
		const whileLockedRes = await SELF.fetch("http://example.com/api/login", {
			method: "POST",
			headers: { "Content-Type": "application/json" },
			body: JSON.stringify({ username: "CharlieM312", password: "NewSecurePassword123!" }),
		});
		expect(whileLockedRes.status).toBe(429);

		// Logout
		const logoutRes = await SELF.fetch("http://example.com/api/logout", {
			method: "POST",
			headers: { Authorization: `Bearer ${ secondLoginData.token }` },
		});
		expect(logoutRes.status).toBe(200);
	});

	it("handles account registration, admin approval/rejection, username renaming, and user deletion", async () => {
		await env.DB.prepare("DELETE FROM users").run();
		await env.DB.prepare(
			"INSERT INTO users (username, password, role, status) VALUES ('CharlieM312', 'adminPassword123', 'admin', 'approved')"
		).run();

		const adminLogin = await SELF.fetch("http://example.com/api/login", {
			method: "POST",
			headers: { "Content-Type": "application/json" },
			body: JSON.stringify({ username: "CharlieM312", password: "adminPassword123" }),
		});
		const { token: adminToken } = await adminLogin.json();

		// 1. Request a new account via POST /api/register
		const regRes = await SELF.fetch("http://example.com/api/register", {
			method: "POST",
			headers: { "Content-Type": "application/json" },
			body: JSON.stringify({
				username: "pending_pilot",
				password: "pilotPassword123",
				email: "pilot@example.com",
			}),
		});
		expect(regRes.status).toBe(202);
		const regBody = await regRes.json();
		expect(regBody.pending_approval).toBe(true);

		// Duplicate registration returns 409
		const dupRes = await SELF.fetch("http://example.com/api/register", {
			method: "POST",
			headers: { "Content-Type": "application/json" },
			body: JSON.stringify({
				username: "pending_pilot",
				password: "pilotPassword123",
			}),
		});
		expect(dupRes.status).toBe(409);

		// 2. Pending user cannot log in before admin approval (403)
		const earlyLogin = await SELF.fetch("http://example.com/api/login", {
			method: "POST",
			headers: { "Content-Type": "application/json" },
			body: JSON.stringify({ username: "pending_pilot", password: "pilotPassword123" }),
		});
		expect(earlyLogin.status).toBe(403);

		// 3. Admin lists pending users via GET /api/admin/users?status=pending
		const listPending = await SELF.fetch("http://example.com/api/admin/users?status=pending", {
			headers: { Authorization: `Bearer ${adminToken}` },
		});
		expect(listPending.status).toBe(200);
		const pendingData = await listPending.json();
		expect(pendingData.pending_count).toBe(1);

		// 4. Admin approves and renames the user via PATCH /api/admin/users/pending_pilot
		const approveRes = await SELF.fetch("http://example.com/api/admin/users/pending_pilot", {
			method: "PATCH",
			headers: {
				"Content-Type": "application/json",
				Authorization: `Bearer ${adminToken}`,
			},
			body: JSON.stringify({
				status: "approved",
				role: "user",
				new_username: "approved_pilot",
			}),
		});
		expect(approveRes.status).toBe(200);
		const approveData = await approveRes.json();
		expect(approveData.username).toBe("approved_pilot");

		// 5. Approved user can now sign in and rename their own username
		const pilotLogin = await SELF.fetch("http://example.com/api/login", {
			method: "POST",
			headers: { "Content-Type": "application/json" },
			body: JSON.stringify({ username: "approved_pilot", password: "pilotPassword123" }),
		});
		expect(pilotLogin.status).toBe(200);
		const { token: pilotToken } = await pilotLogin.json();

		// Non-admin user cannot access /api/admin/users (403)
		const forbiddenAdmin = await SELF.fetch("http://example.com/api/admin/users", {
			headers: { Authorization: `Bearer ${pilotToken}` },
		});
		expect(forbiddenAdmin.status).toBe(403);

		// Self-service rename via PATCH /api/user/username
		const selfRename = await SELF.fetch("http://example.com/api/user/username", {
			method: "PATCH",
			headers: {
				"Content-Type": "application/json",
				Authorization: `Bearer ${pilotToken}`,
			},
			body: JSON.stringify({ new_username: "captain_pilot" }),
		});
		expect(selfRename.status).toBe(200);

		// 6. Admin rejects and then deletes the user
		const rejectRes = await SELF.fetch("http://example.com/api/admin/users/captain_pilot", {
			method: "PATCH",
			headers: {
				"Content-Type": "application/json",
				Authorization: `Bearer ${adminToken}`,
			},
			body: JSON.stringify({ status: "rejected" }),
		});
		expect(rejectRes.status).toBe(200);

		const delUserRes = await SELF.fetch("http://example.com/api/admin/users/captain_pilot", {
			method: "DELETE",
			headers: { Authorization: `Bearer ${adminToken}` },
		});
		expect(delUserRes.status).toBe(200);
	});

	it("enrolls, verifies, enforces, and disables TOTP 2FA and WebAuthn passkeys", async () => {
		await env.DB.prepare("DELETE FROM users").run();
		await env.DB.prepare(
			"INSERT INTO users (username, password, role, status) VALUES ('CharlieM312', 'totpPassword123', 'admin', 'approved')"
		).run();

		const loginRes = await SELF.fetch("http://example.com/api/login", {
			method: "POST",
			headers: { "Content-Type": "application/json" },
			body: JSON.stringify({ username: "CharlieM312", password: "totpPassword123" }),
		});
		const { token } = await loginRes.json();

		// 1. Setup TOTP -> generates pending secret
		const setupRes = await SELF.fetch("http://example.com/api/2fa/totp/setup", {
			method: "POST",
			headers: { Authorization: `Bearer ${token}` },
		});
		expect(setupRes.status).toBe(200);
		const setupData = await setupRes.json();
		expect(setupData.secret).toBeTruthy();
		expect(setupData.pending_verification).toBe(true);

		// Verify with wrong code fails (400)
		const badVerify = await SELF.fetch("http://example.com/api/2fa/totp/verify", {
			method: "POST",
			headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` },
			body: JSON.stringify({ code: "000000" }),
		});
		expect(badVerify.status).toBe(400);

		// Verify with valid 6-digit TOTP code activates 2FA
		const validCode = await generateTotpCodeForTest(setupData.secret);
		const goodVerify = await SELF.fetch("http://example.com/api/2fa/totp/verify", {
			method: "POST",
			headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` },
			body: JSON.stringify({ code: validCode }),
		});
		expect(goodVerify.status).toBe(200);

		// 2. Login without totp_code now returns 401 with requires_totp: true
		const missingTotpLogin = await SELF.fetch("http://example.com/api/login", {
			method: "POST",
			headers: { "Content-Type": "application/json" },
			body: JSON.stringify({ username: "CharlieM312", password: "totpPassword123" }),
		});
		expect(missingTotpLogin.status).toBe(401);
		const missingTotpData = await missingTotpLogin.json();
		expect(missingTotpData.requires_totp).toBe(true);

		// Login with valid totp_code succeeds
		const totpLogin = await SELF.fetch("http://example.com/api/login", {
			method: "POST",
			headers: { "Content-Type": "application/json" },
			body: JSON.stringify({
				username: "CharlieM312",
				password: "totpPassword123",
				totp_code: validCode,
			}),
		});
		expect(totpLogin.status).toBe(200);

		// 3. WebAuthn Passkey enrollment & ECDSA P-256 signature verification
		const regOptsRes = await SELF.fetch("http://example.com/api/webauthn/register-options", {
			method: "POST",
			headers: { Authorization: `Bearer ${token}`, Origin: "https://charlie-meader.com" },
		});
		expect(regOptsRes.status).toBe(200);
		const regOpts = await regOptsRes.json();
		expect(regOpts.rpId).toBe("charlie-meader.com");

		// Generate a real ECDSA P-256 keypair in Web Crypto
		const keyPair = await crypto.subtle.generateKey(
			{ name: "ECDSA", namedCurve: "P-256" },
			true,
			["sign", "verify"]
		);
		const spkiBuffer = await crypto.subtle.exportKey("spki", keyPair.publicKey);
		const publicKeyBase64Url = bytesToBase64Url(new Uint8Array(spkiBuffer));
		const credentialId = "test-yubikey-cred-1";

		const regVerifyRes = await SELF.fetch("http://example.com/api/webauthn/register-verify", {
			method: "POST",
			headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` },
			body: JSON.stringify({
				credential_id: credentialId,
				public_key: publicKeyBase64Url,
				label: "YubiKey 5C NFC",
			}),
		});
		expect(regVerifyRes.status).toBe(200);

		// Edit passkey label
		const editKeyRes = await SELF.fetch("http://example.com/api/webauthn/edit-options", {
			method: "PATCH",
			headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` },
			body: JSON.stringify({ credential_id: credentialId, label: "Primary YubiKey" }),
		});
		expect(editKeyRes.status).toBe(200);

		// WebAuthn login flow: get challenge -> sign with ECDSA P-256 -> verify
		const loginOptsRes = await SELF.fetch("http://example.com/api/webauthn/login-options", {
			method: "POST",
			headers: { "Content-Type": "application/json" },
			body: JSON.stringify({ username: "CharlieM312" }),
		});
		expect(loginOptsRes.status).toBe(200);
		const loginOpts = await loginOptsRes.json();

		const authDataBytes = new Uint8Array(37);
		const clientDataBytes = new TextEncoder().encode(
			JSON.stringify({
				type: "webauthn.get",
				challenge: loginOpts.challenge,
				origin: "https://charlie-meader.com",
			})
		);
		const clientDataHash = new Uint8Array(
			await crypto.subtle.digest("SHA-256", clientDataBytes)
		);
		const signedData = new Uint8Array(authDataBytes.length + clientDataHash.length);
		signedData.set(authDataBytes, 0);
		signedData.set(clientDataHash, authDataBytes.length);

		const p1363Sig = new Uint8Array(
			await crypto.subtle.sign(
				{ name: "ECDSA", hash: "SHA-256" },
				keyPair.privateKey,
				signedData
			)
		);
		const derSig = p1363ToDerSignature(p1363Sig);

		const webauthnVerifyRes = await SELF.fetch("http://example.com/api/webauthn/login-verify", {
			method: "POST",
			headers: { "Content-Type": "application/json" },
			body: JSON.stringify({
				username: "CharlieM312",
				credential_id: credentialId,
				authenticator_data: bytesToBase64Url(authDataBytes),
				client_data_json: bytesToBase64Url(clientDataBytes),
				signature: bytesToBase64Url(derSig),
			}),
		});
		expect(webauthnVerifyRes.status).toBe(200);
		const webauthnLoginData = await webauthnVerifyRes.json();
		expect(webauthnLoginData.token).toBeTruthy();

		// 4. Disable TOTP and WebAuthn
		const delTotp = await SELF.fetch("http://example.com/api/2fa/totp", {
			method: "DELETE",
			headers: { Authorization: `Bearer ${token}` },
		});
		expect(delTotp.status).toBe(200);

		const delWebauthn = await SELF.fetch(
			`http://example.com/api/webauthn?credential_id=${credentialId}`,
			{
				method: "DELETE",
				headers: { Authorization: `Bearer ${token}` },
			}
		);
		expect(delWebauthn.status).toBe(200);
	});

	it("handles OAuth state generation, OIDC id_token login, pending queue, and account linking/unlinking", async () => {
		await env.DB.prepare("DELETE FROM users").run();
		await env.DB.prepare(
			"INSERT INTO users (username, password, role, status) VALUES ('CharlieM312', 'adminPass123', 'admin', 'approved')"
		).run();

		const adminLogin = await SELF.fetch("http://example.com/api/login", {
			method: "POST",
			headers: { "Content-Type": "application/json" },
			body: JSON.stringify({ username: "CharlieM312", password: "adminPass123" }),
		});
		const { token: adminToken } = await adminLogin.json();

		// 1. Get OAuth providers & CSRF state
		const optsRes = await SELF.fetch("http://example.com/api/oauth/providers?provider=google");
		expect(optsRes.status).toBe(200);
		const optsData = await optsRes.json();
		expect(optsData.state).toBeTruthy();

		// 2. New Google user signs in with an OIDC id_token -> creates 'pending' user (202)
		const googleIdToken = createFakeJwt({
			iss: "https://accounts.google.com",
			sub: "google-uid-999",
			email: "traveler@gmail.com",
			name: "Global Traveler",
			exp: Math.floor(Date.now() / 1000) + 3600,
		});

		const oauthLoginRes = await SELF.fetch("http://example.com/api/oauth/login", {
			method: "POST",
			headers: { "Content-Type": "application/json" },
			body: JSON.stringify({
				provider: "google",
				state: optsData.state,
				id_token: googleIdToken,
			}),
		});
		expect(oauthLoginRes.status).toBe(202);
		const oauthPending = await oauthLoginRes.json();
		expect(oauthPending.pending_approval).toBe(true);

		// Admin approves the new OAuth user
		await SELF.fetch(`http://example.com/api/admin/users/${oauthPending.username}`, {
			method: "PATCH",
			headers: { "Content-Type": "application/json", Authorization: `Bearer ${adminToken}` },
			body: JSON.stringify({ status: "approved" }),
		});

		// Subsequent OAuth login now issues a session token (200)
		const approvedOAuthLogin = await SELF.fetch("http://example.com/api/oauth/login", {
			method: "POST",
			headers: { "Content-Type": "application/json" },
			body: JSON.stringify({
				provider: "google",
				id_token: googleIdToken,
			}),
		});
		expect(approvedOAuthLogin.status).toBe(200);
		const approvedOAuthData = await approvedOAuthLogin.json();
		expect(approvedOAuthData.token).toBeTruthy();

		// 3. Link & unlink a Microsoft account on the admin user
		const linkRes = await SELF.fetch("http://example.com/api/oauth/link", {
			method: "POST",
			headers: { "Content-Type": "application/json", Authorization: `Bearer ${adminToken}` },
			body: JSON.stringify({
				provider: "microsoft",
				provider_user_id: "charlie@outlook.com",
				display_name: "Charlie Outlook",
			}),
		});
		expect(linkRes.status).toBe(200);
		const linkData = await linkRes.json();
		expect(linkData.oauth_accounts.some((a) => a.provider === "microsoft")).toBe(true);

		const unlinkRes = await SELF.fetch("http://example.com/api/oauth/link?provider=microsoft", {
			method: "DELETE",
			headers: { Authorization: `Bearer ${adminToken}` },
		});
		expect(unlinkRes.status).toBe(200);
	});

	it("manages reference airports, logs single/batch/GPS visits, computes Haversine distances, and serves stats", async () => {
		await env.DB.prepare("DELETE FROM airport_visits").run();
		await env.DB.prepare("DELETE FROM airports").run();
		await env.DB.prepare("DELETE FROM users").run();
		await env.DB.prepare(
			"INSERT INTO users (username, password, role, status) VALUES ('CharlieM312', 'flightPass123', 'admin', 'approved')"
		).run();

		const loginRes = await SELF.fetch("http://example.com/api/login", {
			method: "POST",
			headers: { "Content-Type": "application/json" },
			body: JSON.stringify({ username: "CharlieM312", password: "flightPass123" }),
		});
		const { token } = await loginRes.json();

		// 1. Seed airports via POST /api/airports
		const seedAirportsRes = await SELF.fetch("http://example.com/api/airports", {
			method: "POST",
			headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` },
			body: JSON.stringify({
				airports: [
					{ iata_code: "LHR", name: "London Heathrow Airport", city: "London", country: "United Kingdom", latitude: 51.47, longitude: -0.4543 },
					{ iata_code: "HAM", name: "Hamburg Airport", city: "Hamburg", country: "Germany", latitude: 53.6304, longitude: 9.9882 },
					{ iata_code: "LTN", name: "London Luton Airport", city: "London", country: "United Kingdom", latitude: 51.8747, longitude: -0.3683 },
					{ iata_code: "AMS", name: "Amsterdam Airport Schiphol", city: "Amsterdam", country: "Netherlands", latitude: 52.3086, longitude: 4.7639 },
				],
			}),
		});
		expect(seedAirportsRes.status).toBe(200);

		// 2. Query airports by code, search, and GPS coordinates
		const codeLookup = await SELF.fetch("http://example.com/api/airports?code=LHR");
		expect(codeLookup.status).toBe(200);
		expect((await codeLookup.json())[0].iata_code).toBe("LHR");

		const searchLookup = await SELF.fetch("http://example.com/api/airports?search=Hamburg");
		expect(searchLookup.status).toBe(200);
		expect((await searchLookup.json())[0].iata_code).toBe("HAM");

		const gpsLookup = await SELF.fetch("http://example.com/api/airports?lat=51.47&lon=-0.45&limit=2");
		expect(gpsLookup.status).toBe(200);
		const gpsAirports = await gpsLookup.json();
		expect(gpsAirports[0].iata_code).toBe("LHR");
		expect(gpsAirports[0].distance_from_location_km).toBeLessThan(5);

		// 3. Log a single visit with origin_iata (LHR -> HAM)
		const visitRes = await SELF.fetch("http://example.com/api/visits", {
			method: "POST",
			headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` },
			body: JSON.stringify({
				iata_code: "HAM",
				origin_iata: "LHR",
				visit_date: "2026-09-15",
				flight_number: "BA968",
				notes: "First flight",
			}),
		});
		expect(visitRes.status).toBe(200);
		const visitData = await visitRes.json();
		expect(visitData.distance_km).toBeGreaterThan(700);

		// 4. One-tap GPS check-in with auto_origin: true (at AMS, auto-detects previous airport HAM as origin!)
		const gpsVisitRes = await SELF.fetch("http://example.com/api/visits", {
			method: "POST",
			headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` },
			body: JSON.stringify({
				latitude: 52.3086,
				longitude: 4.7639,
				auto_origin: true,
				notes: "GPS check-in at Schiphol",
			}),
		});
		expect(gpsVisitRes.status).toBe(200);
		const gpsVisitData = await gpsVisitRes.json();
		expect(gpsVisitData.iata_code).toBe("AMS");
		expect(gpsVisitData.origin_iata).toBe("HAM");
		expect(gpsVisitData.detected_from_gps).toBe(true);

		// 5. Batch insert visits via POST /api/visits/batch
		const batchRes = await SELF.fetch("http://example.com/api/visits/batch", {
			method: "POST",
			headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` },
			body: JSON.stringify({
				visits: [
					{ iata_code: "LHR", origin_iata: "AMS", visit_date: "2026-10-01", flight_number: "KL1001" },
				],
			}),
		});
		expect(batchRes.status).toBe(200);

		// 6. Edit a visit via PATCH /api/visits/:id
		const patchRes = await SELF.fetch(`http://example.com/api/visits/${visitData.id}`, {
			method: "PATCH",
			headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` },
			body: JSON.stringify({
				notes: "Updated flight notes",
				origin_iata: "LTN",
			}),
		});
		expect(patchRes.status).toBe(200);

		// 7. Read visits, visited airports, flight history lookup, and travel stats
		const listVisits = await SELF.fetch("http://example.com/api/visits?username=CharlieM312");
		expect(listVisits.status).toBe(200);
		expect((await listVisits.json()).length).toBe(3);

		const distinctAirports = await SELF.fetch(
			"http://example.com/api/visits/airports?username=CharlieM312&distinct=true"
		);
		expect(distinctAirports.status).toBe(200);
		expect((await distinctAirports.json()).length).toBe(3);

		const statsRes = await SELF.fetch("http://example.com/api/stats?username=CharlieM312");
		expect(statsRes.status).toBe(200);
		const statsData = await statsRes.json();
		expect(statsData.total_visits).toBe(3);
		expect(statsData.unique_airports).toBe(3);
		expect(statsData.total_distance_km).toBeGreaterThan(1000);

		// 8. Delete visit via DELETE /api/visits/:id
		const delVisitRes = await SELF.fetch(`http://example.com/api/visits/${visitData.id}`, {
			method: "DELETE",
			headers: { Authorization: `Bearer ${token}` },
		});
		expect(delVisitRes.status).toBe(200);
	});
});
