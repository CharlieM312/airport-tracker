/**
 * Airport Tracker Worker API
 *
 * Authentication, 2FA, WebAuthn, OAuth & Admin Approval Endpoints:
 * - POST   /api/login                     (Validates username, PBKDF2/plaintext password, brute-force lockout, approval status, and optional TOTP)
 * - POST   /api/register                  (Creates a 'pending' account request with PBKDF2-hashed password awaiting admin approval)
 * - POST   /api/logout                    (Revokes the active session token in `user_sessions` and `users`)
 * - PATCH  /api/user/username             (Protected: renames the signed-in user across all tables)
 * - PATCH  /api/user/password             (Protected: changes or sets the signed-in user's password using PBKDF2-SHA256)
 * - GET    /api/sessions                  (Protected: lists active multi-device sessions for the signed-in user)
 * - DELETE /api/sessions                  (Protected: revokes a specific session by id or all other sessions)
 * - GET    /api/api-keys                  (Protected: lists personal access tokens / API keys for the signed-in user)
 * - POST   /api/api-keys                  (Protected: generates a new `atk_...` personal access token)
 * - DELETE /api/api-keys                  (Protected: revokes a personal access token by id)
 * - GET    /api/oauth/providers           (Public: lists supported OAuth providers [github, google, microsoft, apple] & client IDs)
 * - POST   /api/oauth/options             (Public: generates CSRF state nonce & returns provider config)
 * - POST   /api/oauth/login               (Public: signs in an approved OAuth user or creates a 'pending' account for admin approval)
 * - POST   /api/oauth/link                (Protected: links a GitHub/Google/Microsoft/Apple identity to the signed-in user)
 * - DELETE /api/oauth/link                (Protected: unlinks an OAuth provider from the signed-in user)
 * - GET    /api/admin/users               (Admin: lists users & pending approval requests)
 * - PATCH  /api/admin/users               (Admin: approves/rejects a user, updates their role, or renames their username)
 * - DELETE /api/admin/users               (Admin: deletes a pending/rejected user account)
 * - GET    /api/2fa/status                (Protected: returns { totp_enabled, webauthn_enabled, passkeys, oauth_accounts, role, status })
 * - POST   /api/2fa/totp/setup            (Protected: generates pending Base32 TOTP secret & otpauth:// URI)
 * - POST   /api/2fa/totp/verify           (Protected: verifies a 6-digit code and activates totp_secret)
 * - DELETE /api/2fa/totp                  (Protected: disables Authenticator TOTP 2FA)
 * - DELETE /api/webauthn                  (Protected: removes registered YubiKey / security key)
 * - DELETE /api/2fa                       (Protected: disables TOTP, WebAuthn, or both)
 * - POST   /api/webauthn/register-options (Protected: generates challenge to enroll a YubiKey / Passkey)
 * - POST   /api/webauthn/register-verify  (Protected: saves YubiKey credential_id & SPKI public_key)
 * - POST   /api/webauthn/login-options    (Public: generates challenge & allowCredentials for YubiKey sign-in)
 * - POST   /api/webauthn/login-verify     (Public: verifies YubiKey ECDSA/RSA signature & issues session token)
 *
 * Public Read Endpoints:
 * - GET /api/visits          (?username=&limit=&before=)
 * - GET /api/visits/airports (?username=&distinct=true)
 * - GET /api/stats           (?username=)
 * - GET /api/airports        (?code=LHR or ?search=London)
 *
 * Protected Write Endpoints (Authorization: Bearer <session_token>):
 * - POST   /api/visits       (Single visit insert; uses authenticated user's username)
 * - POST   /api/visits/batch (Bulk insert visits using D1 db.batch())
 * - PATCH  /api/visits       (or PATCH /api/visits/:id — update an existing visit)
 * - DELETE /api/visits       (or DELETE /api/visits/:id — delete a visit)
 * - POST   /api/airports     (Single or batch upsert into the airports reference table)
 */

const EARTH_RADIUS_KM = 6371;
const KM_TO_MILES = 0.621371;
const BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
const PBKDF2_ITERATIONS = 100000;
const SESSION_TTL_MS = 30 * 24 * 60 * 60 * 1000; // 30 days
const MAX_FAILED_LOGIN_ATTEMPTS = 5;
const LOCKOUT_DURATION_MS = 15 * 60 * 1000; // 15 minutes

const CORS_HEADERS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, PATCH, PUT, DELETE, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Authorization, x-d1-bookmark",
};

function jsonResponse(data, init = {}) {
  const headers = {
    ...CORS_HEADERS,
    ...(init.headers || {}),
  };
  if (data && typeof data === "object" && !Array.isArray(data)) {
    if (data.error && !data.message) {
      data = { ...data, message: data.error };
    }
  }
  return Response.json(data, { ...init, headers });
}

// ============================================================================
// TOTP & WebAuthn Cryptographic Helpers (Web Crypto API)
// ============================================================================

function generateBase32Secret(byteLength = 20) {
  const bytes = crypto.getRandomValues(new Uint8Array(byteLength));
  let bits = 0;
  let value = 0;
  let output = "";
  for (const byte of bytes) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      output += BASE32_ALPHABET[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) {
    output += BASE32_ALPHABET[(value << (5 - bits)) & 31];
  }
  return output;
}

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

async function generateTotpCode(secretBase32, counter) {
  const keyBytes = base32ToBytes(secretBase32);
  const counterBytes = new ArrayBuffer(8);
  const view = new DataView(counterBytes);
  view.setUint32(4, counter, false);

  const cryptoKey = await crypto.subtle.importKey(
    "raw",
    keyBytes,
    { name: "HMAC", hash: "SHA-1" },
    false,
    ["sign"]
  );
  const hmac = new Uint8Array(await crypto.subtle.sign("HMAC", cryptoKey, counterBytes));
  const offset = hmac[hmac.length - 1] & 0x0f;
  const binary =
    ((hmac[offset] & 0x7f) << 24) |
    ((hmac[offset + 1] & 0xff) << 16) |
    ((hmac[offset + 2] & 0xff) << 8) |
    (hmac[offset + 3] & 0xff);
  return String(binary % 1_000_000).padStart(6, "0");
}

async function verifyTotp(secretBase32, code) {
  const cleanCode = String(code || "").trim();
  if (!/^\d{6}$/.test(cleanCode)) return false;
  const currentStep = Math.floor(Date.now() / 30000);
  // Allow +/- 1 time step (30s window) for clock drift
  for (const offset of [-1, 0, 1]) {
    if ((await generateTotpCode(secretBase32, currentStep + offset)) === cleanCode) {
      return true;
    }
  }
  return false;
}

function base64UrlToBytes(base64Url) {
  const str = String(base64Url || "");
  const padding = "=".repeat((4 - (str.length % 4)) % 4);
  const base64 = (str + padding).replace(/-/g, "+").replace(/_/g, "/");
  const raw = atob(base64);
  const out = new Uint8Array(raw.length);
  for (let i = 0; i < raw.length; i++) {
    out[i] = raw.charCodeAt(i);
  }
  return out;
}

function bytesToBase64Url(bytes) {
  let binary = "";
  for (const b of bytes) {
    binary += String.fromCharCode(b);
  }
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/**
 * Compute SHA-256 hex digest using Web Crypto (used for hashing API keys).
 */
async function sha256Hex(input) {
  const bytes = new TextEncoder().encode(String(input || ""));
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return Array.from(new Uint8Array(digest))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

/**
 * Check whether a stored password value is already in PBKDF2 format (`pbkdf2$<iterations>$<salt>$<hash>`).
 */
function isHashedPassword(stored) {
  return typeof stored === "string" && stored.startsWith("pbkdf2$");
}

/**
 * Hash a plaintext password using Web Crypto PBKDF2-SHA256.
 */
async function hashPassword(plainPassword, saltBytes = null, iterations = PBKDF2_ITERATIONS) {
  const salt = saltBytes || crypto.getRandomValues(new Uint8Array(16));
  const baseKey = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(String(plainPassword)),
    { name: "PBKDF2" },
    false,
    ["deriveBits"]
  );
  const derivedBits = await crypto.subtle.deriveBits(
    {
      name: "PBKDF2",
      salt,
      iterations,
      hash: "SHA-256",
    },
    baseKey,
    256
  );
  return `pbkdf2$${iterations}$${bytesToBase64Url(salt)}$${bytesToBase64Url(
    new Uint8Array(derivedBits)
  )}`;
}

/**
 * Verify a user's password against either a PBKDF2 hash or a legacy plaintext password.
 * Automatically upgrades legacy plaintext passwords in D1 to PBKDF2-SHA256 upon successful verification.
 */
async function verifyUserPassword(db, user, inputPassword) {
  if (!user || !user.password || !inputPassword) {
    return false;
  }

  const stored = String(user.password);
  if (isHashedPassword(stored)) {
    const parts = stored.split("$");
    if (parts.length !== 4) return false;
    const iterations = parseInt(parts[1], 10) || PBKDF2_ITERATIONS;
    const salt = base64UrlToBytes(parts[2]);
    const expectedHash = await hashPassword(inputPassword, salt, iterations);
    if (expectedHash.length !== stored.length) return false;
    let diff = 0;
    for (let i = 0; i < stored.length; i++) {
      diff |= stored.charCodeAt(i) ^ expectedHash.charCodeAt(i);
    }
    return diff === 0;
  }

  // Legacy plaintext comparison + automatic upgrade to PBKDF2-SHA256
  if (stored === String(inputPassword)) {
    try {
      const upgradedHash = await hashPassword(inputPassword);
      await db
        .prepare("UPDATE users SET password = ? WHERE username = ?")
        .bind(upgradedHash, user.username)
        .run();
    } catch {
      // Non-fatal if upgrade write fails
    }
    return true;
  }

  return false;
}

/**
 * Convert WebAuthn ASN.1 DER ECDSA signature into 64-byte IEEE P1363 (r || s) format for Web Crypto.
 */
function derToP1363Signature(derBytes) {
  let offset = 2;
  if (derBytes[1] & 0x80) {
    offset += derBytes[1] & 0x7f;
  }
  const rLen = derBytes[offset + 1];
  let r = derBytes.slice(offset + 2, offset + 2 + rLen);
  offset += 2 + rLen;
  const sLen = derBytes[offset + 1];
  let s = derBytes.slice(offset + 2, offset + 2 + sLen);

  if (r.length > 32) r = r.slice(r.length - 32);
  if (s.length > 32) s = s.slice(s.length - 32);

  const raw = new Uint8Array(64);
  raw.set(r, 32 - r.length);
  raw.set(s, 64 - s.length);
  return raw;
}

/**
 * Determine the Relying Party ID (rpId) from the browser Origin header (fallback to request URL hostname).
 */
function getRpId(request, url) {
  const origin = request.headers.get("Origin");
  if (origin) {
    try {
      return new URL(origin).hostname;
    } catch {
      // Fallback to url.hostname
    }
  }
  return url.hostname;
}

/**
 * Ensure the `user_passkeys` table exists and return all registered passkeys for a username.
 */
async function getUserPasskeys(db, username) {
  await db
    .prepare(
      `CREATE TABLE IF NOT EXISTS user_passkeys (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL REFERENCES users(username) ON DELETE CASCADE ON UPDATE CASCADE,
        credential_id TEXT NOT NULL UNIQUE,
        public_key TEXT NOT NULL,
        label TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
      )`
    )
    .run();

  const { results } = await db
    .prepare(
      "SELECT id, credential_id, public_key, label, created_at FROM user_passkeys WHERE username = ? ORDER BY id ASC"
    )
    .bind(username)
    .all();

  return results || [];
}

const SUPPORTED_OAUTH_PROVIDERS = ["github", "google", "microsoft", "apple"];

/**
 * Ensure `user_oauth_accounts` and `oauth_states` tables exist.
 */
async function ensureOAuthTables(db) {
  try {
    await db
      .prepare("ALTER TABLE users ADD COLUMN role TEXT NOT NULL DEFAULT 'user'")
      .run();
  } catch {
    // Column already exists
  }
  try {
    await db
      .prepare("ALTER TABLE users ADD COLUMN status TEXT NOT NULL DEFAULT 'approved'")
      .run();
  } catch {
    // Column already exists
  }
  try {
    await db.prepare("ALTER TABLE users ADD COLUMN email TEXT").run();
  } catch {
    // Column already exists
  }

  await db
    .prepare(
      `CREATE TABLE IF NOT EXISTS user_oauth_accounts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL REFERENCES users(username) ON DELETE CASCADE ON UPDATE CASCADE,
        provider TEXT NOT NULL,
        provider_user_id TEXT NOT NULL,
        email TEXT,
        display_name TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(provider, provider_user_id)
      )`
    )
    .run();

  await db
    .prepare(
      `CREATE TABLE IF NOT EXISTS oauth_states (
        state TEXT PRIMARY KEY,
        provider TEXT NOT NULL,
        redirect_uri TEXT,
        link_username TEXT,
        created_at INTEGER NOT NULL
      )`
    )
    .run();
}

/**
 * Ensure security hardening columns (`failed_login_attempts`, `locked_until`) and tables
 * (`user_sessions`, `user_api_keys`) exist.
 */
async function ensureSecurityTables(db) {
  try {
    await db
      .prepare(
        "ALTER TABLE users ADD COLUMN failed_login_attempts INTEGER NOT NULL DEFAULT 0"
      )
      .run();
  } catch {
    // Column already exists
  }
  try {
    await db
      .prepare("ALTER TABLE users ADD COLUMN locked_until INTEGER")
      .run();
  } catch {
    // Column already exists
  }

  await db
    .prepare(
      `CREATE TABLE IF NOT EXISTS user_sessions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL REFERENCES users(username) ON DELETE CASCADE ON UPDATE CASCADE,
        token TEXT NOT NULL UNIQUE,
        user_agent TEXT,
        ip_address TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        last_used_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        expires_at INTEGER NOT NULL
      )`
    )
    .run();

  await db
    .prepare(
      `CREATE TABLE IF NOT EXISTS user_api_keys (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL REFERENCES users(username) ON DELETE CASCADE ON UPDATE CASCADE,
        label TEXT NOT NULL,
        key_prefix TEXT NOT NULL,
        key_hash TEXT NOT NULL UNIQUE,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        last_used_at DATETIME,
        expires_at INTEGER
      )`
    )
    .run();

  // Auto-migrate any existing plain-text passwords in `users` to PBKDF2-SHA256
  try {
    const { results: plainUsers } = await db
      .prepare(
        "SELECT username, password FROM users WHERE password IS NOT NULL AND password != '' AND password NOT LIKE 'pbkdf2$%'"
      )
      .all();

    for (const row of plainUsers || []) {
      if (row.password && !isHashedPassword(row.password)) {
        const hashed = await hashPassword(row.password);
        await db
          .prepare("UPDATE users SET password = ? WHERE username = ?")
          .bind(hashed, row.username)
          .run();
      }
    }
  } catch {
    // Non-fatal if users table is not initialized yet
  }
}

/**
 * Check if a user account is currently locked due to brute-force login attempts.
 */
function checkAccountLockout(user) {
  if (!user || !user.locked_until) return null;
  const lockedUntilMs = Number(user.locked_until);
  const nowMs = Date.now();
  if (Number.isFinite(lockedUntilMs) && lockedUntilMs > nowMs) {
    const retryAfterSeconds = Math.max(1, Math.ceil((lockedUntilMs - nowMs) / 1000));
    const minutes = Math.ceil(retryAfterSeconds / 60);
    return jsonResponse(
      {
        error: `Too many failed login attempts. Account is locked for ${minutes} minute(s).`,
        locked: true,
        retry_after_seconds: retryAfterSeconds,
      },
      { status: 429 }
    );
  }
  return null;
}

/**
 * Increment failed login attempts and lock the account for 15 minutes after 5 consecutive failures.
 */
async function recordFailedLoginAttempt(db, user) {
  if (!user || !user.username) return null;
  await ensureSecurityTables(db);
  const nowMs = Date.now();
  // If a previous lockout already expired, restart counter at 1
  const wasExpiredLock =
    user.locked_until && Number(user.locked_until) <= nowMs;
  const baseAttempts = wasExpiredLock
    ? 0
    : Number(user.failed_login_attempts || 0);
  const nextAttempts = baseAttempts + 1;
  const lockedUntil =
    nextAttempts >= MAX_FAILED_LOGIN_ATTEMPTS
      ? nowMs + LOCKOUT_DURATION_MS
      : null;

  await db
    .prepare(
      "UPDATE users SET failed_login_attempts = ?, locked_until = ? WHERE username = ?"
    )
    .bind(nextAttempts, lockedUntil, user.username)
    .run();

  return {
    attempts: nextAttempts,
    locked: Boolean(lockedUntil),
    locked_until: lockedUntil,
    remaining_attempts: Math.max(0, MAX_FAILED_LOGIN_ATTEMPTS - nextAttempts),
  };
}

/**
 * Reset failed login counter and clear any lockout after a successful sign-in.
 */
async function clearFailedLoginAttempts(db, username) {
  try {
    await ensureSecurityTables(db);
    await db
      .prepare(
        "UPDATE users SET failed_login_attempts = 0, locked_until = NULL WHERE username = ?"
      )
      .bind(username)
      .run();
  } catch {
    // Non-fatal
  }
}

/**
 * Create a new multi-device session row in `user_sessions` (and update `users.session_token` for compatibility).
 */
async function createUserSession(db, request, username) {
  await ensureSecurityTables(db);
  const sessionToken = crypto.randomUUID();
  const nowMs = Date.now();
  const expiresAt = nowMs + SESSION_TTL_MS;
  const userAgent =
    (request.headers.get("User-Agent") || "Browser").slice(0, 255);
  const ipAddress =
    request.headers.get("CF-Connecting-IP") ||
    request.headers.get("X-Forwarded-For") ||
    null;

  // Prune any expired sessions for cleanliness
  await db
    .prepare("DELETE FROM user_sessions WHERE expires_at < ?")
    .bind(nowMs)
    .run();

  await db
    .prepare(
      `INSERT INTO user_sessions (username, token, user_agent, ip_address, expires_at)
       VALUES (?, ?, ?, ?, ?)`
    )
    .bind(username, sessionToken, userAgent, ipAddress, expiresAt)
    .run();

  await db
    .prepare("UPDATE users SET session_token = ? WHERE username = ?")
    .bind(sessionToken, username)
    .run();

  return { token: sessionToken, expires_at: expiresAt };
}

/**
 * Return all linked OAuth accounts for a username.
 */
async function getUserOAuthAccounts(db, username) {
  await ensureOAuthTables(db);
  const { results } = await db
    .prepare(
      "SELECT id, provider, provider_user_id, email, display_name, created_at FROM user_oauth_accounts WHERE username = ? ORDER BY id ASC"
    )
    .bind(username)
    .all();
  return results || [];
}

/**
 * Determine whether a user row has administrator privileges.
 */
function isUserAdmin(user) {
  if (!user) return false;
  if (user.isApiSecret) return true;
  if (user.role === "admin") return true;
  if (user.username === "CharlieM312" || Number(user.id) === 1) return true;
  return false;
}

/**
 * Decode and validate an OpenID Connect JWT `id_token` (Google, Microsoft, Apple).
 */
function decodeAndValidateIdToken(idToken, provider, env) {
  const parts = String(idToken || "").split(".");
  if (parts.length < 2) {
    throw new Error("Invalid OIDC id_token format");
  }
  const payloadBytes = base64UrlToBytes(parts[1]);
  const claims = JSON.parse(new TextDecoder().decode(payloadBytes));

  const nowSeconds = Math.floor(Date.now() / 1000);
  if (claims.exp && Number(claims.exp) < nowSeconds - 60) {
    throw new Error("OAuth id_token has expired");
  }

  const iss = String(claims.iss || "").toLowerCase();
  if (provider === "google" && iss && !iss.includes("accounts.google.com")) {
    throw new Error("Invalid Google id_token issuer");
  }
  if (
    provider === "microsoft" &&
    iss &&
    !iss.includes("microsoftonline.com") &&
    !iss.includes("sts.windows.net") &&
    !iss.includes("live.com")
  ) {
    throw new Error("Invalid Microsoft id_token issuer");
  }
  if (provider === "apple" && iss && !iss.includes("appleid.apple.com")) {
    throw new Error("Invalid Apple id_token issuer");
  }

  const expectedClientId =
    provider === "google"
      ? env.GOOGLE_CLIENT_ID
      : provider === "microsoft"
      ? env.MICROSOFT_CLIENT_ID
      : provider === "apple"
      ? env.APPLE_CLIENT_ID
      : provider === "github"
      ? env.GITHUB_CLIENT_ID
      : null;

  if (expectedClientId && claims.aud && claims.aud !== expectedClientId) {
    const audList = Array.isArray(claims.aud) ? claims.aud : [claims.aud];
    if (!audList.includes(expectedClientId)) {
      throw new Error(`OAuth id_token audience does not match configured ${provider} client ID`);
    }
  }

  return {
    provider_user_id: String(claims.sub || claims.oid || claims.id || ""),
    email: claims.email || claims.preferred_username || null,
    display_name: claims.name || claims.preferred_username || claims.email || null,
  };
}

/**
 * Exchange a GitHub OAuth authorization `code` for an access token and fetch the GitHub user profile.
 */
async function exchangeGitHubCode(code, redirectUri, env) {
  if (!env.GITHUB_CLIENT_ID || !env.GITHUB_CLIENT_SECRET) {
    throw new Error(
      "GITHUB_CLIENT_ID and GITHUB_CLIENT_SECRET must be configured on the Worker"
    );
  }

  const tokenPayload = {
    client_id: env.GITHUB_CLIENT_ID,
    client_secret: env.GITHUB_CLIENT_SECRET,
    code: String(code).trim(),
  };
  if (redirectUri) {
    tokenPayload.redirect_uri = redirectUri;
  }

  const tokenRes = await fetch("https://github.com/login/oauth/access_token", {
    method: "POST",
    headers: {
      Accept: "application/json",
      "Content-Type": "application/json",
      "User-Agent": "Airport-Tracker-Worker",
    },
    body: JSON.stringify(tokenPayload),
  });

  const tokenData = await tokenRes.json();
  if (!tokenRes.ok || !tokenData.access_token) {
    throw new Error(
      tokenData.error_description ||
        tokenData.error ||
        "Failed to exchange GitHub OAuth code for access token"
    );
  }

  const userRes = await fetch("https://api.github.com/user", {
    headers: {
      Authorization: `Bearer ${tokenData.access_token}`,
      Accept: "application/vnd.github+json",
      "User-Agent": "Airport-Tracker-Worker",
    },
  });

  const ghUser = await userRes.json();
  if (!userRes.ok || !ghUser || !ghUser.id) {
    throw new Error(ghUser?.message || "Failed to fetch GitHub user profile");
  }

  let primaryEmail = ghUser.email || null;
  if (!primaryEmail) {
    try {
      const emailsRes = await fetch("https://api.github.com/user/emails", {
        headers: {
          Authorization: `Bearer ${tokenData.access_token}`,
          Accept: "application/vnd.github+json",
          "User-Agent": "Airport-Tracker-Worker",
        },
      });
      if (emailsRes.ok) {
        const emails = await emailsRes.json();
        if (Array.isArray(emails)) {
          const found =
            emails.find((e) => e.primary && e.verified) ||
            emails.find((e) => e.verified) ||
            emails[0];
          if (found && found.email) {
            primaryEmail = found.email;
          }
        }
      }
    } catch {
      // Optional email lookup fallback
    }
  }

  return {
    provider_user_id: String(ghUser.id),
    email: primaryEmail,
    display_name: ghUser.login || ghUser.name || null,
    username: ghUser.login || null,
  };
}

/**
 * Exchange a Microsoft (Entra / Personal) OAuth authorization `code` for an `id_token` / profile.
 */
async function exchangeMicrosoftCode(code, redirectUri, env) {
  if (!env.MICROSOFT_CLIENT_ID || !env.MICROSOFT_CLIENT_SECRET) {
    throw new Error(
      "MICROSOFT_CLIENT_ID and MICROSOFT_CLIENT_SECRET must be configured on the Worker"
    );
  }

  const form = new URLSearchParams({
    client_id: env.MICROSOFT_CLIENT_ID,
    client_secret: env.MICROSOFT_CLIENT_SECRET,
    code: String(code).trim(),
    grant_type: "authorization_code",
    scope: "openid profile email User.Read",
  });
  if (redirectUri) {
    form.set("redirect_uri", redirectUri);
  }

  const tokenRes = await fetch(
    "https://login.microsoftonline.com/common/oauth2/v2.0/token",
    {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
      },
      body: form.toString(),
    }
  );

  const tokenData = await tokenRes.json();
  if (!tokenRes.ok || (!tokenData.id_token && !tokenData.access_token)) {
    throw new Error(
      tokenData.error_description ||
        tokenData.error ||
        "Failed to exchange Microsoft OAuth code"
    );
  }

  if (tokenData.id_token) {
    return decodeAndValidateIdToken(tokenData.id_token, "microsoft", env);
  }

  const graphRes = await fetch("https://graph.microsoft.com/v1.0/me", {
    headers: {
      Authorization: `Bearer ${tokenData.access_token}`,
    },
  });
  const msUser = await graphRes.json();
  if (!graphRes.ok || !msUser || !msUser.id) {
    throw new Error("Failed to fetch Microsoft user profile");
  }

  return {
    provider_user_id: String(msUser.id),
    email: msUser.mail || msUser.userPrincipalName || null,
    display_name: msUser.displayName || msUser.userPrincipalName || null,
  };
}

/**
 * Exchange a Google OAuth 2.0 authorization `code` for an `id_token` / user profile.
 */
async function exchangeGoogleCode(code, redirectUri, env) {
  if (!env.GOOGLE_CLIENT_ID || !env.GOOGLE_CLIENT_SECRET) {
    throw new Error(
      "GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET must be configured on the Worker"
    );
  }

  const form = new URLSearchParams({
    client_id: env.GOOGLE_CLIENT_ID,
    client_secret: env.GOOGLE_CLIENT_SECRET,
    code: String(code).trim(),
    grant_type: "authorization_code",
  });
  if (redirectUri) {
    form.set("redirect_uri", redirectUri);
  }

  const tokenRes = await fetch("https://oauth2.googleapis.com/token", {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
    },
    body: form.toString(),
  });

  const tokenData = await tokenRes.json();
  if (!tokenRes.ok || (!tokenData.id_token && !tokenData.access_token)) {
    throw new Error(
      tokenData.error_description ||
        tokenData.error ||
        "Failed to exchange Google OAuth code for token"
    );
  }

  if (tokenData.id_token) {
    return decodeAndValidateIdToken(tokenData.id_token, "google", env);
  }

  const userRes = await fetch(
    "https://openidconnect.googleapis.com/v1/userinfo",
    {
      headers: {
        Authorization: `Bearer ${tokenData.access_token}`,
      },
    }
  );
  const gUser = await userRes.json();
  if (!userRes.ok || !gUser || !gUser.sub) {
    throw new Error("Failed to fetch Google user profile");
  }

  return {
    provider_user_id: String(gUser.sub),
    email: gUser.email || null,
    display_name: gUser.name || gUser.email || null,
  };
}

/**
 * Generate a unique username in `users` from a desired name / email / OAuth login.
 */
async function resolveUniqueUsername(db, rawBaseName) {
  const cleaned = String(rawBaseName || "user")
    .split("@")[0]
    .replace(/[^a-zA-Z0-9_-]/g, "")
    .slice(0, 24) || "user";

  let candidate = cleaned;
  let suffix = 2;
  while (true) {
    const existing = await db
      .prepare("SELECT username FROM users WHERE LOWER(username) = LOWER(?)")
      .bind(candidate)
      .first();
    if (!existing) return candidate;
    candidate = `${cleaned}_${suffix}`;
    suffix++;
  }
}

/**
 * Validate and rename a username across `users`, `airport_visits`, `user_passkeys`, and `user_oauth_accounts`.
 */
async function renameUsernameInDb(db, oldUsername, rawNewUsername) {
  const newUsername = String(rawNewUsername || "").trim();
  if (!newUsername) {
    return { error: "New username is required", status: 400 };
  }
  if (!/^[a-zA-Z0-9_.-]{2,32}$/.test(newUsername)) {
    return {
      error:
        "Username must be 2–32 characters and contain only letters, numbers, underscores, hyphens, or dots",
      status: 400,
    };
  }

  if (newUsername === oldUsername) {
    return { username: newUsername, changed: false };
  }

  // Check if another user already has this username (case-insensitive, allowing casing changes on own username)
  const conflict = await db
    .prepare(
      "SELECT username FROM users WHERE LOWER(username) = LOWER(?) AND LOWER(username) != LOWER(?)"
    )
    .bind(newUsername, oldUsername)
    .first();

  if (conflict) {
    return { error: `Username '${newUsername}' is already taken`, status: 409 };
  }

  await getUserPasskeys(db, oldUsername);
  await ensureOAuthTables(db);
  await ensureSecurityTables(db);

  await db.batch([
    db.prepare("PRAGMA defer_foreign_keys = ON"),
    db
      .prepare("UPDATE users SET username = ? WHERE username = ?")
      .bind(newUsername, oldUsername),
    db
      .prepare("UPDATE airport_visits SET username = ? WHERE username = ?")
      .bind(newUsername, oldUsername),
    db
      .prepare("UPDATE user_passkeys SET username = ? WHERE username = ?")
      .bind(newUsername, oldUsername),
    db
      .prepare("UPDATE user_oauth_accounts SET username = ? WHERE username = ?")
      .bind(newUsername, oldUsername),
    db
      .prepare("UPDATE user_sessions SET username = ? WHERE username = ?")
      .bind(newUsername, oldUsername),
    db
      .prepare("UPDATE user_api_keys SET username = ? WHERE username = ?")
      .bind(newUsername, oldUsername),
  ]);

  return { username: newUsername, changed: true };
}

/**
 * Calculate great-circle distance between two coordinates using the Haversine formula.
 */
function calculateDistanceKm(lat1, lon1, lat2, lon2) {
  if (
    lat1 == null ||
    lon1 == null ||
    lat2 == null ||
    lon2 == null ||
    !Number.isFinite(Number(lat1)) ||
    !Number.isFinite(Number(lon1)) ||
    !Number.isFinite(Number(lat2)) ||
    !Number.isFinite(Number(lon2))
  ) {
    return null;
  }
  const toRad = (deg) => (Number(deg) * Math.PI) / 180;
  const dLat = toRad(lat2 - lat1);
  const dLon = toRad(lon2 - lon1);
  const a =
    Math.sin(dLat / 2) ** 2 +
    Math.cos(toRad(lat1)) * Math.cos(toRad(lat2)) * Math.sin(dLon / 2) ** 2;
  const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
  return Math.round(EARTH_RADIUS_KM * c * 10) / 10;
}

/**
 * Verify Bearer token against `users.session_token` in D1 (with fallback to env.API_SECRET).
 * Returns `{ user, errorResponse }`.
 */
async function authenticateRequest(request, env, db) {
  const authHeader = request.headers.get("Authorization");
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return {
      user: null,
      errorResponse: jsonResponse({ error: "Unauthorized: Missing token" }, { status: 401 }),
    };
  }

  const token = authHeader.slice("Bearer ".length).trim();
  if (!token) {
    return {
      user: null,
      errorResponse: jsonResponse({ error: "Unauthorized: Missing token" }, { status: 401 }),
    };
  }

  // 1. Check if token is a Personal Access Token / API key (`atk_...`)
  if (token.startsWith("atk_")) {
    try {
      await ensureSecurityTables(db);
      const keyHash = await sha256Hex(token);
      const apiKeyRow = await db
        .prepare("SELECT * FROM user_api_keys WHERE key_hash = ?")
        .bind(keyHash)
        .first();

      if (!apiKeyRow) {
        return {
          user: null,
          errorResponse: jsonResponse(
            { error: "Unauthorized: Invalid or revoked API key" },
            { status: 401 }
          ),
        };
      }

      if (apiKeyRow.expires_at && Number(apiKeyRow.expires_at) < Date.now()) {
        return {
          user: null,
          errorResponse: jsonResponse(
            { error: "Unauthorized: API key has expired" },
            { status: 401 }
          ),
        };
      }

      const user = await db
        .prepare("SELECT * FROM users WHERE username = ?")
        .bind(apiKeyRow.username)
        .first();

      if (!user) {
        return {
          user: null,
          errorResponse: jsonResponse(
            { error: "Unauthorized: User for API key not found" },
            { status: 401 }
          ),
        };
      }

      const accountStatus = user.status || "approved";
      if (accountStatus !== "approved") {
        return {
          user: null,
          errorResponse: jsonResponse(
            {
              error: "Account is not approved",
              status: accountStatus,
            },
            { status: 403 }
          ),
        };
      }

      await db
        .prepare(
          "UPDATE user_api_keys SET last_used_at = CURRENT_TIMESTAMP WHERE id = ?"
        )
        .bind(apiKeyRow.id)
        .run();

      user.isAdmin = isUserAdmin(user);
      user.role = user.isAdmin ? "admin" : user.role || "user";
      user.status = accountStatus;
      user.authType = "api_key";
      user.apiKeyId = apiKeyRow.id;
      return { user, errorResponse: null };
    } catch {
      // Fall through if user_api_keys table check fails
    }
  }

  // 2. Check multi-device `user_sessions` table (with 30-day expiry)
  try {
    await ensureSecurityTables(db);
    const sessionRow = await db
      .prepare("SELECT * FROM user_sessions WHERE token = ?")
      .bind(token)
      .first();

    if (sessionRow) {
      if (sessionRow.expires_at && Number(sessionRow.expires_at) < Date.now()) {
        await db
          .prepare("DELETE FROM user_sessions WHERE id = ?")
          .bind(sessionRow.id)
          .run();
        return {
          user: null,
          errorResponse: jsonResponse(
            { error: "Unauthorized: Session has expired" },
            { status: 401 }
          ),
        };
      }

      const user = await db
        .prepare("SELECT * FROM users WHERE username = ?")
        .bind(sessionRow.username)
        .first();

      if (user) {
        const accountStatus = user.status || "approved";
        if (accountStatus !== "approved") {
          return {
            user: null,
            errorResponse: jsonResponse(
              {
                error:
                  accountStatus === "pending"
                    ? "Your account is awaiting admin approval"
                    : "Your account is not approved",
                status: accountStatus,
                pending_approval: accountStatus === "pending",
              },
              { status: 403 }
            ),
          };
        }

        await db
          .prepare(
            "UPDATE user_sessions SET last_used_at = CURRENT_TIMESTAMP WHERE id = ?"
          )
          .bind(sessionRow.id)
          .run();

        user.isAdmin = isUserAdmin(user);
        user.role = user.isAdmin ? "admin" : user.role || "user";
        user.status = accountStatus;
        user.currentSessionToken = token;
        user.currentSessionId = sessionRow.id;
        return { user, errorResponse: null };
      }
    }
  } catch {
    // Fall through to legacy session_token check
  }

  // 3. Fallback: check legacy `users.session_token` column
  try {
    const user = await db
      .prepare("SELECT * FROM users WHERE session_token = ?")
      .bind(token)
      .first();

    if (user) {
      const accountStatus = user.status || "approved";
      if (accountStatus !== "approved") {
        return {
          user: null,
          errorResponse: jsonResponse(
            {
              error:
                accountStatus === "pending"
                  ? "Your account is awaiting admin approval"
                  : "Your account is not approved",
              status: accountStatus,
              pending_approval: accountStatus === "pending",
            },
            { status: 403 }
          ),
        };
      }
      user.isAdmin = isUserAdmin(user);
      user.role = user.isAdmin ? "admin" : user.role || "user";
      user.status = accountStatus;
      user.currentSessionToken = token;
      return { user, errorResponse: null };
    }
  } catch {
    // If users table does not exist yet, fall through to API_SECRET check
  }

  // 2. Fallback: allow static env.API_SECRET for CLI / administrative tasks if configured
  if (env.API_SECRET && token === env.API_SECRET) {
    return {
      user: { username: null, isApiSecret: true, isAdmin: true, role: "admin" },
      errorResponse: null,
    };
  }

  return {
    user: null,
    errorResponse: jsonResponse(
      { error: "Unauthorized: Invalid or expired session" },
      { status: 401 }
    ),
  };
}

/**
 * Invalidate cached GET responses when data changes.
 */
function invalidateVisitCaches(cache, origin, usernames = []) {
  const urlsToPurge = new Set([
    `${origin}/api/visits`,
    `${origin}/api/visits/airports`,
    `${origin}/api/visits/airports?distinct=true`,
    `${origin}/api/stats`,
  ]);

  for (const username of usernames) {
    if (username) {
      const encoded = encodeURIComponent(username);
      urlsToPurge.add(`${origin}/api/visits?username=${encoded}`);
      urlsToPurge.add(`${origin}/api/visits/airports?username=${encoded}`);
      urlsToPurge.add(`${origin}/api/visits/airports?username=${encoded}&distinct=true`);
      urlsToPurge.add(`${origin}/api/stats?username=${encoded}`);
    }
  }

  return Promise.all([...urlsToPurge].map((u) => cache.delete(u)));
}

/**
 * Fetch reference airport metadata for a set of IATA codes in a single query.
 */
async function lookupAirportsMap(db, codes) {
  const uniqueCodes = [
    ...new Set(
      codes
        .filter(Boolean)
        .map((c) => String(c).trim().toUpperCase())
        .filter((c) => c.length > 0)
    ),
  ];
  const map = new Map();
  if (uniqueCodes.length === 0) return map;

  try {
    const placeholders = uniqueCodes.map(() => "?").join(", ");
    const { results } = await db
      .prepare(
        `SELECT iata_code, name, city, country, latitude, longitude FROM airports WHERE iata_code IN (${placeholders})`
      )
      .bind(...uniqueCodes)
      .all();

    for (const row of results || []) {
      map.set(row.iata_code.toUpperCase(), row);
    }
  } catch {
    // Gracefully continue if airports reference table migration hasn't been applied yet
  }
  return map;
}

/**
 * Find the closest airports in the `airports` reference table to a given GPS (latitude, longitude) point.
 */
async function findNearestAirports(db, lat, lon, limit = 5) {
  const numLat = Number(lat);
  const numLon = Number(lon);
  if (!Number.isFinite(numLat) || !Number.isFinite(numLon)) {
    return [];
  }

  // Coarse bounding-box filter (~3 degrees lat/lon around the point) with fallback to full table scan
  const { results } = await db
    .prepare(
      "SELECT iata_code, name, city, country, latitude, longitude FROM airports WHERE latitude IS NOT NULL AND longitude IS NOT NULL"
    )
    .all();

  const ranked = [];
  for (const row of results || []) {
    const distKm = calculateDistanceKm(numLat, numLon, row.latitude, row.longitude);
    if (distKm != null) {
      ranked.push({
        ...row,
        distance_from_location_km: distKm,
        distance_from_location_miles: Math.round(distKm * KM_TO_MILES * 10) / 10,
      });
    }
  }

  ranked.sort((a, b) => a.distance_from_location_km - b.distance_from_location_km);
  return ranked.slice(0, Math.max(1, Math.min(limit, 50)));
}

/**
 * Common 2-letter IATA airline code -> 3-letter ICAO callsign prefix map
 * so IATA flight numbers like `BA968`, `U28541`, or `FR1234` resolve cleanly against ADSBdb.
 */
const IATA_TO_ICAO_AIRLINES = {
  BA: "BAW",
  U2: "EZY",
  EZ: "EZY",
  FR: "RYR",
  RK: "RUK",
  VS: "VIR",
  EI: "EIN",
  LS: "EXS",
  BY: "TOM",
  MT: "TOM",
  LM: "LOG",
  SI: "BCI",
  GR: "AUR",
  T3: "EZE",
  KL: "KLM",
  LH: "DLH",
  EW: "EWG",
  AF: "AFR",
  IB: "IBE",
  VY: "VLG",
  UX: "AEA",
  AZ: "ITY",
  LX: "SWR",
  OS: "AUA",
  SN: "BEL",
  SK: "SAS",
  AY: "FIN",
  DY: "NOZ",
  D8: "NSZ",
  TP: "TAP",
  A3: "AEE",
  LO: "LOT",
  BT: "BTI",
  W6: "WZZ",
  W9: "WUK",
  W4: "WMT",
  FI: "ICE",
  TK: "THY",
  PC: "PGT",
  AA: "AAL",
  DL: "DAL",
  UA: "UAL",
  WN: "SWA",
  B6: "JBU",
  AS: "ASA",
  AC: "ACA",
  WS: "WJA",
  EK: "UAE",
  QR: "QTR",
  EY: "ETD",
  SQ: "SIA",
  CX: "CPA",
  QF: "QFA",
  NZ: "ANZ",
  NH: "ANA",
  JL: "JAL",
};

/**
 * Resolve a flight number / callsign (e.g., `BA968` or `BAW968`) to its origin and destination IATA codes.
 * 1. Queries the free public ADSBdb Callsign API (`https://api.adsbdb.com/v0/callsign/{CALLSIGN}`)
 *    and automatically upserts any missing origin/destination airport into the D1 `airports` reference table.
 * 2. Falls back to previously logged flights with the same `flight_number` in D1 `airport_visits`.
 */
async function resolveFlightRoute(db, rawFlightNumber) {
  const cleaned = String(rawFlightNumber || "")
    .trim()
    .toUpperCase()
    .replace(/\s+/g, "");
  if (!cleaned) return null;

  // Build candidate callsigns to try (e.g. BA968 -> ["BAW968", "BA968"], W43304 -> ["WMT3304", "WZZ3304", "WUK3304", "W43304"])
  const candidates = [];
  const match = cleaned.match(/^([A-Z]{3}|[A-Z0-9]{2})0*(\d+[A-Z]?)$/);
  if (match) {
    const [, prefix, numPart] = match;
    const mappedIcao = IATA_TO_ICAO_AIRLINES[prefix];
    if (mappedIcao) {
      candidates.push(`${mappedIcao}${numPart}`);
    }
    // Multi-subsidiary European carriers (Wizz Air: WMT/WZZ/WUK, easyJet: EZY/EJU/EZS, Ryanair: RYR/RUK)
    if (["W4", "W6", "W9", "WMT", "WZZ", "WUK"].includes(prefix)) {
      for (const sub of ["WMT", "WZZ", "WUK"]) {
        if (!candidates.includes(`${sub}${numPart}`)) candidates.push(`${sub}${numPart}`);
      }
    } else if (["U2", "EZ", "EZY", "EJU", "EZS"].includes(prefix)) {
      for (const sub of ["EZY", "EJU", "EZS"]) {
        if (!candidates.includes(`${sub}${numPart}`)) candidates.push(`${sub}${numPart}`);
      }
    } else if (["FR", "RK", "RYR", "RUK"].includes(prefix)) {
      for (const sub of ["RYR", "RUK"]) {
        if (!candidates.includes(`${sub}${numPart}`)) candidates.push(`${sub}${numPart}`);
      }
    }
    if (!candidates.includes(`${prefix}${numPart}`)) {
      candidates.push(`${prefix}${numPart}`);
    }
  }
  if (!candidates.includes(cleaned)) {
    candidates.push(cleaned);
  }

  for (const callsign of candidates) {
    try {
      const res = await fetch(
        `https://api.adsbdb.com/v0/callsign/${encodeURIComponent(callsign)}`,
        {
          headers: {
            Accept: "application/json",
            "User-Agent": "Airport-Tracker-Worker",
          },
        }
      );
      if (!res.ok) continue;

      const data = await res.json();
      const route = data?.response?.flightroute;
      if (!route) continue;

      const orig = route.origin || null;
      const dest = route.destination || null;
      const origIata = orig?.iata_code
        ? String(orig.iata_code).trim().toUpperCase()
        : null;
      const destIata = dest?.iata_code
        ? String(dest.iata_code).trim().toUpperCase()
        : null;

      if (!origIata && !destIata) continue;

      // Auto-upsert origin and destination airports into `airports` reference table so foreign keys & distances always work
      for (const ap of [orig, dest]) {
        if (
          ap &&
          ap.iata_code &&
          ap.name &&
          ap.latitude != null &&
          ap.longitude != null
        ) {
          try {
            await db
              .prepare(
                `INSERT INTO airports (iata_code, name, city, country, latitude, longitude)
                 VALUES (?, ?, ?, ?, ?, ?)
                 ON CONFLICT(iata_code) DO NOTHING`
              )
              .bind(
                String(ap.iata_code).trim().toUpperCase(),
                ap.name,
                ap.municipality || null,
                ap.country_name || null,
                Number(ap.latitude),
                Number(ap.longitude)
              )
              .run();
          } catch {
            // Non-fatal if airports table is read-only or unavailable
          }
        }
      }

      return {
        source: "adsbdb",
        flight_number: cleaned,
        callsign_icao: route.callsign_icao || callsign,
        callsign_iata: route.callsign_iata || cleaned,
        airline_name: route.airline?.name || null,
        origin_iata: origIata,
        origin_name: orig?.name || null,
        origin_city: orig?.municipality || null,
        origin_country: orig?.country_name || null,
        destination_iata: destIata,
        destination_name: dest?.name || null,
        destination_city: dest?.municipality || null,
        destination_country: dest?.country_name || null,
        distance_km:
          orig?.latitude != null && dest?.latitude != null
            ? calculateDistanceKm(
                orig.latitude,
                orig.longitude,
                dest.latitude,
                dest.longitude
              )
            : null,
      };
    } catch {
      // Try next candidate or fall back to local D1 history
    }
  }

  // Fallback: check if this flight_number has ever been logged in `airport_visits`
  try {
    const previous = await db
      .prepare(
        `SELECT origin_iata, iata_code, distance_km
         FROM airport_visits
         WHERE UPPER(flight_number) = ? AND origin_iata IS NOT NULL
         ORDER BY visit_date DESC, id DESC
         LIMIT 1`
      )
      .bind(cleaned)
      .first();

    if (previous) {
      return {
        source: "history",
        flight_number: cleaned,
        origin_iata: previous.origin_iata
          ? String(previous.origin_iata).trim().toUpperCase()
          : null,
        destination_iata: previous.iata_code
          ? String(previous.iata_code).trim().toUpperCase()
          : null,
        distance_km: previous.distance_km ?? null,
      };
    }
  } catch {
    // Non-fatal
  }

  return null;
}

/**
 * Verify a reCAPTCHA Enterprise (or v3 siteverify) token and return { ok, score, action, errorResponse }.
 */
async function verifyRecaptchaToken(
  request,
  env,
  recaptchaToken,
  expectedActions = ["signup", "register", "login", "password_reset"]
) {
  const apiKey =
    env.RECAPTCHA_API_KEY ||
    (env.RECAPTCHA_SECRET_KEY &&
    String(env.RECAPTCHA_SECRET_KEY).startsWith("AIza")
      ? env.RECAPTCHA_SECRET_KEY
      : null);
  const legacySecret =
    !apiKey && env.RECAPTCHA_SECRET_KEY ? env.RECAPTCHA_SECRET_KEY : null;

  if (!apiKey && !legacySecret) {
    return { ok: true, skipped: true };
  }

  if (!recaptchaToken) {
    return {
      ok: false,
      errorResponse: jsonResponse(
        { error: "reCAPTCHA verification token is required" },
        { status: 400 }
      ),
    };
  }

  const normalizedAllowed = expectedActions.map((a) =>
    String(a).toLowerCase()
  );
  const primaryExpectedAction = normalizedAllowed[0] || "login";
  const minScore = Number(env.RECAPTCHA_MIN_SCORE || 0.5);

  if (apiKey) {
    const siteKey =
      env.RECAPTCHA_SITE_KEY || "6LcFGiwuAAAAAFMGjXiXaqEilTTODLbSAXiqYBRI";
    const projectId = env.RECAPTCHA_PROJECT_ID || "charliem312-website";
    const assessmentRes = await fetch(
      `https://recaptchaenterprise.googleapis.com/v1/projects/${projectId}/assessments?key=${encodeURIComponent(apiKey)}`,
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          event: {
            token: String(recaptchaToken),
            expectedAction: primaryExpectedAction,
            siteKey,
          },
        }),
      }
    );

    const assessmentData = await assessmentRes.json();
    const tokenProps = assessmentData?.tokenProperties;
    const score = assessmentData?.riskAnalysis?.score;
    const returnedAction = tokenProps?.action
      ? String(tokenProps.action).toLowerCase()
      : "";
    const actionMatches =
      !returnedAction || normalizedAllowed.includes(returnedAction);

    if (
      !assessmentRes.ok ||
      !tokenProps?.valid ||
      !actionMatches ||
      (typeof score === "number" && score < minScore)
    ) {
      return {
        ok: false,
        score: score ?? null,
        action: returnedAction || null,
        errorResponse: jsonResponse(
          {
            error:
              "reCAPTCHA Enterprise verification failed. Automated request blocked.",
            invalid_reason: tokenProps?.invalidReason || null,
          },
          { status: 403 }
        ),
      };
    }

    return {
      ok: true,
      score: score ?? null,
      action: returnedAction || primaryExpectedAction,
    };
  }

  const verifyForm = new URLSearchParams({
    secret: legacySecret,
    response: String(recaptchaToken),
  });
  const clientIp = request.headers.get("CF-Connecting-IP");
  if (clientIp) {
    verifyForm.set("remoteip", clientIp);
  }
  const verifyRes = await fetch(
    "https://www.google.com/recaptcha/api/siteverify",
    {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: verifyForm.toString(),
    }
  );
  const verifyData = await verifyRes.json();
  if (
    !verifyData.success ||
    (typeof verifyData.score === "number" && verifyData.score < minScore)
  ) {
    return {
      ok: false,
      score: verifyData.score ?? null,
      errorResponse: jsonResponse(
        { error: "reCAPTCHA verification failed. Automated request blocked." },
        { status: 403 }
      ),
    };
  }

  return {
    ok: true,
    score: verifyData.score ?? null,
    action: verifyData.action || primaryExpectedAction,
  };
}

export default {
  async fetch(request, env, ctx) {
    // Handle CORS preflight requests
    if (request.method === "OPTIONS") {
      return new Response(null, { status: 204, headers: CORS_HEADERS });
    }

    const url = new URL(request.url);
    const cache = caches.default;

    // Use D1 Sessions API for Global Read Replication support (with fallback)
    const bookmark = request.headers.get("x-d1-bookmark") ?? "first-unconstrained";
    const db = typeof env.DB.withSession === "function" ? env.DB.withSession(bookmark) : env.DB;

    const cacheHeaders = () => ({
      ...CORS_HEADERS,
      "Cache-Control": "public, max-age=60, s-maxage=300, stale-while-revalidate=600",
      ...(typeof db.getBookmark === "function" && db.getBookmark()
        ? { "x-d1-bookmark": db.getBookmark() }
        : {}),
    });

    // =========================================================================
    // POST /api/recaptcha/assess - Verify a reCAPTCHA Enterprise token & request score
    // =========================================================================
    if (request.method === "POST" && url.pathname === "/api/recaptcha/assess") {
      try {
        const body = await request.json();
        const token = body.recaptcha_token || body.token || "";
        const action = body.action ? String(body.action).toLowerCase() : "login";
        const result = await verifyRecaptchaToken(request, env, token, [
          action,
          "login",
          "signup",
          "register",
          "password_reset",
        ]);
        if (!result.ok && result.errorResponse) {
          return result.errorResponse;
        }
        return jsonResponse({
          success: true,
          score: result.score ?? null,
          action: result.action || action,
        });
      } catch (err) {
        return jsonResponse({ error: err.message }, { status: 500 });
      }
    }

    // =========================================================================
    // POST /api/login - Validate credentials (+ optional TOTP) & issue session token
    // =========================================================================
    if (request.method === "POST" && url.pathname === "/api/login") {
      try {
        const body = await request.json();
        const { username, password, totp_code, recaptcha_token } = body;

        if (!username || !password) {
          return jsonResponse(
            { error: "Username and password are required" },
            { status: 400 }
          );
        }

        if (recaptcha_token) {
          const recaptchaCheck = await verifyRecaptchaToken(
            request,
            env,
            recaptcha_token,
            ["login"]
          );
          if (!recaptchaCheck.ok && recaptchaCheck.errorResponse) {
            return recaptchaCheck.errorResponse;
          }
        }

        await ensureSecurityTables(db);
        const user = await db
          .prepare("SELECT * FROM users WHERE username = ?")
          .bind(username)
          .first();

        if (!user) {
          return jsonResponse(
            { error: "Invalid username or password" },
            { status: 401 }
          );
        }

        // Check if account is temporarily locked due to brute-force attempts
        const lockoutResponse = checkAccountLockout(user);
        if (lockoutResponse) return lockoutResponse;

        // Verify password against PBKDF2-SHA256 hash (or auto-migrate legacy plaintext password)
        const isPasswordValid = await verifyUserPassword(db, user, password);
        if (!isPasswordValid) {
          const failInfo = await recordFailedLoginAttempt(db, user);
          if (failInfo && failInfo.locked) {
            return jsonResponse(
              {
                error: "Too many failed login attempts. Account locked for 15 minutes.",
                locked: true,
                retry_after_seconds: Math.ceil(LOCKOUT_DURATION_MS / 1000),
              },
              { status: 429 }
            );
          }
          return jsonResponse(
            {
              error: "Invalid username or password",
              remaining_attempts: failInfo ? failInfo.remaining_attempts : undefined,
            },
            { status: 401 }
          );
        }

        // Enforce admin approval status before allowing login
        const accountStatus = user.status || "approved";
        if (accountStatus === "pending") {
          return jsonResponse(
            {
              error: "Your account is awaiting admin approval before you can sign in.",
              status: "pending",
              pending_approval: true,
              username: user.username,
            },
            { status: 403 }
          );
        }
        if (accountStatus !== "approved") {
          return jsonResponse(
            {
              error: "Your account request was not approved.",
              status: accountStatus,
            },
            { status: 403 }
          );
        }

        // If user has enrolled Microsoft/Yubico Authenticator TOTP, verify the 6-digit code
        if (user.totp_secret) {
          if (!totp_code) {
            return jsonResponse(
              { error: "6-digit Authenticator code required", requires_totp: true },
              { status: 401 }
            );
          }
          const isValidTotp = await verifyTotp(user.totp_secret, totp_code);
          if (!isValidTotp) {
            const failInfo = await recordFailedLoginAttempt(db, user);
            if (failInfo && failInfo.locked) {
              return jsonResponse(
                {
                  error:
                    "Too many failed Authenticator code attempts. Account locked for 15 minutes.",
                  locked: true,
                  retry_after_seconds: Math.ceil(LOCKOUT_DURATION_MS / 1000),
                },
                { status: 429 }
              );
            }
            return jsonResponse(
              {
                error: "Invalid 6-digit Authenticator code",
                remaining_attempts: failInfo ? failInfo.remaining_attempts : undefined,
              },
              { status: 401 }
            );
          }
        }

        await clearFailedLoginAttempts(db, user.username);
        const session = await createUserSession(db, request, user.username);

        const adminFlag = isUserAdmin(user);
        return jsonResponse({
          success: true,
          token: session.token,
          expires_at: session.expires_at,
          username: user.username,
          role: adminFlag ? "admin" : user.role || "user",
          is_admin: adminFlag,
          status: accountStatus,
        });
      } catch (err) {
        return jsonResponse({ error: err.message }, { status: 500 });
      }
    }

    // =========================================================================
    // POST /api/register - Request a new account (Requires Admin Approval)
    // =========================================================================
    if (request.method === "POST" && url.pathname === "/api/register") {
      try {
        const body = await request.json();
        const { username, password, email, recaptcha_token } = body;
        const cleanUsername = String(username || "").trim();

        if (!cleanUsername || !password) {
          return jsonResponse(
            { error: "Username and password are required" },
            { status: 400 }
          );
        }

        if (String(password).length < 8) {
          return jsonResponse(
            { error: "Password must be at least 8 characters long" },
            { status: 400 }
          );
        }

        // Verify reCAPTCHA Enterprise (or v3 fallback) token when RECAPTCHA_API_KEY or RECAPTCHA_SECRET_KEY is configured
        const recaptchaCheck = await verifyRecaptchaToken(
          request,
          env,
          recaptcha_token,
          ["signup", "register"]
        );
        if (!recaptchaCheck.ok && recaptchaCheck.errorResponse) {
          return recaptchaCheck.errorResponse;
        }

        await ensureOAuthTables(db);
        await ensureSecurityTables(db);

        const existing = await db
          .prepare("SELECT username, status FROM users WHERE LOWER(username) = LOWER(?)")
          .bind(cleanUsername)
          .first();

        if (existing) {
          return jsonResponse(
            { error: "That username is already registered or awaiting approval" },
            { status: 409 }
          );
        }

        const passwordHash = await hashPassword(password);
        await db
          .prepare(
            "INSERT INTO users (username, password, email, role, status) VALUES (?, ?, ?, 'user', 'pending')"
          )
          .bind(cleanUsername, passwordHash, email || null)
          .run();

        return jsonResponse(
          {
            success: true,
            pending_approval: true,
            status: "pending",
            username: cleanUsername,
            message: "Account request submitted. An administrator must approve your account before you can sign in.",
          },
          { status: 202 }
        );
      } catch (err) {
        return jsonResponse({ error: err.message }, { status: 500 });
      }
    }

    // =========================================================================
    // GET /api/oauth/providers & POST /api/oauth/options - OAuth state & config
    // =========================================================================
    if (
      (request.method === "GET" && url.pathname === "/api/oauth/providers") ||
      ((request.method === "GET" || request.method === "POST") &&
        url.pathname === "/api/oauth/options")
    ) {
      try {
        await ensureOAuthTables(db);
        let requestedProvider = url.searchParams.get("provider");
        let redirectUri = url.searchParams.get("redirect_uri");

        if (request.method === "POST") {
          try {
            const body = await request.json();
            requestedProvider = body.provider || requestedProvider;
            redirectUri = body.redirect_uri || redirectUri;
          } catch {
            // Optional JSON body
          }
        }

        const provider = requestedProvider
          ? String(requestedProvider).toLowerCase().trim()
          : "all";

        if (provider !== "all" && !SUPPORTED_OAUTH_PROVIDERS.includes(provider)) {
          return jsonResponse(
            {
              error: `Unsupported OAuth provider '${provider}'. Supported: ${SUPPORTED_OAUTH_PROVIDERS.join(", ")}`,
            },
            { status: 400 }
          );
        }

        const nowMs = Date.now();
        // Clean up expired CSRF states older than 15 minutes
        await db
          .prepare("DELETE FROM oauth_states WHERE created_at < ?")
          .bind(nowMs - 15 * 60 * 1000)
          .run();

        const state = bytesToBase64Url(crypto.getRandomValues(new Uint8Array(24)));
        await db
          .prepare(
            "INSERT INTO oauth_states (state, provider, redirect_uri, created_at) VALUES (?, ?, ?, ?)"
          )
          .bind(state, provider, redirectUri || null, nowMs)
          .run();

        return jsonResponse({
          state,
          providers: {
            github: {
              enabled: true,
              client_id: env.GITHUB_CLIENT_ID || null,
            },
            google: {
              enabled: true,
              client_id: env.GOOGLE_CLIENT_ID || null,
            },
            microsoft: {
              enabled: true,
              client_id: env.MICROSOFT_CLIENT_ID || null,
            },
            apple: {
              enabled: true,
              client_id: env.APPLE_CLIENT_ID || null,
            },
          },
        });
      } catch (err) {
        return jsonResponse({ error: err.message }, { status: 500 });
      }
    }

    // =========================================================================
    // POST /api/oauth/login - Sign in via OAuth or create a 'pending' account
    // =========================================================================
    if (request.method === "POST" && url.pathname === "/api/oauth/login") {
      try {
        await ensureOAuthTables(db);
        const body = await request.json();
        let provider = String(body.provider || "").toLowerCase().trim();

        // Verify one-time CSRF state nonce if supplied (and resolve provider from stateRow if recorded)
        if (body.state) {
          const stateRow = await db
            .prepare("SELECT * FROM oauth_states WHERE state = ?")
            .bind(body.state)
            .first();

          if (!stateRow) {
            return jsonResponse(
              { error: "Invalid or expired OAuth state parameter" },
              { status: 401 }
            );
          }

          if (
            stateRow.provider &&
            stateRow.provider !== "all" &&
            SUPPORTED_OAUTH_PROVIDERS.includes(stateRow.provider)
          ) {
            provider = stateRow.provider;
          }

          await db
            .prepare("DELETE FROM oauth_states WHERE state = ?")
            .bind(body.state)
            .run();
        }

        if (!SUPPORTED_OAUTH_PROVIDERS.includes(provider)) {
          return jsonResponse(
            {
              error: `Invalid or missing OAuth provider. Supported: ${SUPPORTED_OAUTH_PROVIDERS.join(", ")}`,
            },
            { status: 400 }
          );
        }

        let providerUserId = String(body.provider_user_id || body.sub || "").trim();
        let email = body.email ? String(body.email).trim() : null;
        let displayName = body.display_name || body.username || body.name || null;

        // If a GitHub OAuth authorization code was provided, exchange it for the GitHub user profile
        if (provider === "github" && body.code) {
          const ghIdentity = await exchangeGitHubCode(
            body.code,
            body.redirect_uri,
            env
          );
          providerUserId = providerUserId || ghIdentity.provider_user_id;
          email = email || ghIdentity.email;
          displayName = displayName || ghIdentity.display_name;
        }

        // If a Google OAuth authorization code was provided, exchange it for the Google user profile
        if (provider === "google" && body.code) {
          const googleIdentity = await exchangeGoogleCode(
            body.code,
            body.redirect_uri,
            env
          );
          providerUserId = providerUserId || googleIdentity.provider_user_id;
          email = email || googleIdentity.email;
          displayName = displayName || googleIdentity.display_name;
        }

        // If a Microsoft OAuth authorization code was provided, exchange it for the Microsoft user profile
        if (provider === "microsoft" && body.code) {
          const msIdentity = await exchangeMicrosoftCode(
            body.code,
            body.redirect_uri,
            env
          );
          providerUserId = providerUserId || msIdentity.provider_user_id;
          email = email || msIdentity.email;
          displayName = displayName || msIdentity.display_name;
        }

        // If an OpenID Connect id_token JWT was provided (Google, Microsoft, Apple), decode & validate its claims
        if (body.id_token) {
          const tokenIdentity = decodeAndValidateIdToken(body.id_token, provider, env);
          providerUserId = providerUserId || tokenIdentity.provider_user_id;
          email = email || tokenIdentity.email;
          displayName = displayName || tokenIdentity.display_name;
        }

        if (!email && providerUserId.includes("@")) {
          email = providerUserId;
        }
        if (!providerUserId && email) {
          providerUserId = email;
        }

        if (!providerUserId) {
          return jsonResponse(
            { error: "Missing OAuth identity (code, id_token, email, or provider_user_id)" },
            { status: 400 }
          );
        }

        // 1. Check if this OAuth account is already linked to a user (by provider_user_id or email)
        let existingOAuth = await db
          .prepare(
            `SELECT * FROM user_oauth_accounts
             WHERE provider = ?
               AND (
                 LOWER(provider_user_id) = LOWER(?)
                 OR (? IS NOT NULL AND email IS NOT NULL AND LOWER(email) = LOWER(?))
                 OR (? IS NOT NULL AND LOWER(provider_user_id) = LOWER(?))
               )`
          )
          .bind(provider, providerUserId, email, email, email, email)
          .first();

        // Auto-link verified GitHub code login if the GitHub username matches an existing approved admin account (e.g. CharlieM312)
        if (!existingOAuth && body.code && displayName) {
          const matchingAdmin = await db
            .prepare("SELECT * FROM users WHERE LOWER(username) = LOWER(?)")
            .bind(displayName)
            .first();

          if (matchingAdmin && isUserAdmin(matchingAdmin)) {
            await db
              .prepare(
                `INSERT INTO user_oauth_accounts (username, provider, provider_user_id, email, display_name)
                 VALUES (?, ?, ?, ?, ?)
                 ON CONFLICT(provider, provider_user_id) DO UPDATE SET username = excluded.username`
              )
              .bind(
                matchingAdmin.username,
                provider,
                providerUserId,
                email,
                displayName
              )
              .run();

            existingOAuth = { username: matchingAdmin.username };
          }
        }

        if (existingOAuth) {
          const user = await db
            .prepare("SELECT * FROM users WHERE username = ?")
            .bind(existingOAuth.username)
            .first();

          if (!user) {
            return jsonResponse({ error: "Linked user account no longer exists" }, { status: 404 });
          }

          const lockoutResponse = checkAccountLockout(user);
          if (lockoutResponse) return lockoutResponse;

          const accountStatus = user.status || "approved";
          if (accountStatus === "pending") {
            return jsonResponse(
              {
                success: false,
                pending_approval: true,
                status: "pending",
                username: user.username,
                provider,
                error: "Your account is awaiting admin approval before you can sign in.",
              },
              { status: 403 }
            );
          }
          if (accountStatus !== "approved") {
            return jsonResponse(
              {
                success: false,
                status: accountStatus,
                error: "Your account request was not approved by an administrator.",
              },
              { status: 403 }
            );
          }

          // Optional: if the user also has Authenticator TOTP enabled on their account, verify it if required
          if (user.totp_secret && body.totp_code) {
            const isValidTotp = await verifyTotp(user.totp_secret, body.totp_code);
            if (!isValidTotp) {
              const failInfo = await recordFailedLoginAttempt(db, user);
              if (failInfo && failInfo.locked) {
                return jsonResponse(
                  {
                    error:
                      "Too many failed Authenticator code attempts. Account locked for 15 minutes.",
                    locked: true,
                    retry_after_seconds: Math.ceil(LOCKOUT_DURATION_MS / 1000),
                  },
                  { status: 429 }
                );
              }
              return jsonResponse(
                { error: "Invalid 6-digit Authenticator code" },
                { status: 401 }
              );
            }
          }

          await clearFailedLoginAttempts(db, user.username);
          const session = await createUserSession(db, request, user.username);

          const adminFlag = isUserAdmin(user);
          return jsonResponse({
            success: true,
            token: session.token,
            expires_at: session.expires_at,
            username: user.username,
            provider,
            role: adminFlag ? "admin" : user.role || "user",
            is_admin: adminFlag,
            status: accountStatus,
          });
        }

        // 2. New OAuth user: create a 'pending' user in `users` awaiting admin approval!
        const candidateUsername = await resolveUniqueUsername(
          db,
          body.username || displayName || email || `${provider}_user`
        );

        await db
          .prepare(
            "INSERT INTO users (username, password, email, role, status) VALUES (?, '', ?, 'user', 'pending')"
          )
          .bind(candidateUsername, email)
          .run();

        await db
          .prepare(
            `INSERT INTO user_oauth_accounts (username, provider, provider_user_id, email, display_name)
             VALUES (?, ?, ?, ?, ?)`
          )
          .bind(candidateUsername, provider, providerUserId, email, displayName)
          .run();

        return jsonResponse(
          {
            success: false,
            pending_approval: true,
            status: "pending",
            username: candidateUsername,
            provider,
            message:
              "Your OAuth account has been registered and is awaiting admin approval before you can sign in.",
          },
          { status: 202 }
        );
      } catch (err) {
        return jsonResponse({ error: err.message }, { status: 500 });
      }
    }

    // =========================================================================
    // POST /api/oauth/link & DELETE /api/oauth/link - Link/Unlink OAuth (Protected)
    // =========================================================================
    if (
      (request.method === "POST" || request.method === "DELETE") &&
      url.pathname === "/api/oauth/link"
    ) {
      const { user, errorResponse } = await authenticateRequest(request, env, db);
      if (errorResponse) return errorResponse;
      if (!user.username) {
        return jsonResponse(
          { error: "Please sign in with a user account to link OAuth providers" },
          { status: 400 }
        );
      }

      try {
        await ensureOAuthTables(db);

        if (request.method === "DELETE") {
          let body = {};
          try {
            body = await request.json();
          } catch {
            // Optional JSON body
          }
          const provider = String(
            url.searchParams.get("provider") || body.provider || ""
          )
            .toLowerCase()
            .trim();
          const accountId = url.searchParams.get("id") || body.id || null;

          if (accountId) {
            await db
              .prepare("DELETE FROM user_oauth_accounts WHERE username = ? AND id = ?")
              .bind(user.username, accountId)
              .run();
          } else if (provider) {
            await db
              .prepare("DELETE FROM user_oauth_accounts WHERE username = ? AND provider = ?")
              .bind(user.username, provider)
              .run();
          } else {
            return jsonResponse(
              { error: "Specify provider or id to unlink" },
              { status: 400 }
            );
          }

          const updatedAccounts = await getUserOAuthAccounts(db, user.username);
          return jsonResponse({
            success: true,
            oauth_accounts: updatedAccounts,
          });
        }

        // POST /api/oauth/link - Link an OAuth provider to the signed-in user
        const body = await request.json();
        let provider = String(body.provider || "").toLowerCase().trim();

        if (body.state) {
          const stateRow = await db
            .prepare("SELECT * FROM oauth_states WHERE state = ?")
            .bind(body.state)
            .first();

          if (
            stateRow &&
            stateRow.provider &&
            stateRow.provider !== "all" &&
            SUPPORTED_OAUTH_PROVIDERS.includes(stateRow.provider)
          ) {
            provider = stateRow.provider;
          }

          await db
            .prepare("DELETE FROM oauth_states WHERE state = ?")
            .bind(body.state)
            .run();
        }

        if (!SUPPORTED_OAUTH_PROVIDERS.includes(provider)) {
          return jsonResponse(
            {
              error: `Unsupported OAuth provider. Supported: ${SUPPORTED_OAUTH_PROVIDERS.join(", ")}`,
            },
            { status: 400 }
          );
        }

        let providerUserId = String(body.provider_user_id || body.sub || "").trim();
        let email = body.email ? String(body.email).trim() : null;
        let displayName = body.display_name || body.name || null;

        if (provider === "github" && body.code) {
          const ghIdentity = await exchangeGitHubCode(
            body.code,
            body.redirect_uri,
            env
          );
          providerUserId = providerUserId || ghIdentity.provider_user_id;
          email = email || ghIdentity.email;
          displayName = displayName || ghIdentity.display_name;
        }

        if (provider === "google" && body.code) {
          const googleIdentity = await exchangeGoogleCode(
            body.code,
            body.redirect_uri,
            env
          );
          providerUserId = providerUserId || googleIdentity.provider_user_id;
          email = email || googleIdentity.email;
          displayName = displayName || googleIdentity.display_name;
        }

        if (provider === "microsoft" && body.code) {
          const msIdentity = await exchangeMicrosoftCode(
            body.code,
            body.redirect_uri,
            env
          );
          providerUserId = providerUserId || msIdentity.provider_user_id;
          email = email || msIdentity.email;
          displayName = displayName || msIdentity.display_name;
        }

        if (body.id_token) {
          const tokenIdentity = decodeAndValidateIdToken(body.id_token, provider, env);
          providerUserId = providerUserId || tokenIdentity.provider_user_id;
          email = email || tokenIdentity.email;
          displayName = displayName || tokenIdentity.display_name;
        }

        if (!email && providerUserId.includes("@")) {
          email = providerUserId;
        }
        if (!providerUserId && email) {
          providerUserId = email;
        }

        if (!providerUserId) {
          return jsonResponse(
            { error: "Missing required field: code, id_token, email, or provider_user_id" },
            { status: 400 }
          );
        }

        if (email) {
          await db
            .prepare(
              "UPDATE users SET email = COALESCE(email, ?) WHERE username = ?"
            )
            .bind(email, user.username)
            .run();
        }

        await db
          .prepare(
            `INSERT INTO user_oauth_accounts (username, provider, provider_user_id, email, display_name)
             VALUES (?, ?, ?, ?, ?)
             ON CONFLICT(provider, provider_user_id) DO UPDATE SET
               username = excluded.username,
               email = COALESCE(excluded.email, user_oauth_accounts.email),
               display_name = COALESCE(excluded.display_name, user_oauth_accounts.display_name)`
          )
          .bind(user.username, provider, providerUserId, email, displayName)
          .run();

        const updatedAccounts = await getUserOAuthAccounts(db, user.username);
        return jsonResponse({
          success: true,
          oauth_accounts: updatedAccounts,
        });
      } catch (err) {
        return jsonResponse({ error: err.message }, { status: 500 });
      }
    }

    // =========================================================================
    // GET, PATCH, DELETE /api/admin/users - Admin User Approval & Management
    // =========================================================================
    if (
      url.pathname === "/api/admin/users" ||
      url.pathname.startsWith("/api/admin/users/")
    ) {
      const { user, errorResponse } = await authenticateRequest(request, env, db);
      if (errorResponse) return errorResponse;
      if (!isUserAdmin(user)) {
        return jsonResponse(
          { error: "Forbidden: Administrator privileges required" },
          { status: 403 }
        );
      }

      try {
        await ensureOAuthTables(db);

        // 1. GET /api/admin/users - List all users & pending requests
        if (request.method === "GET") {
          const statusFilter = url.searchParams.get("status");
          let query =
            "SELECT id, username, email, role, status, totp_secret, created_at FROM users";
          const params = [];
          if (statusFilter) {
            query += " WHERE status = ?";
            params.push(statusFilter);
          }
          query +=
            " ORDER BY CASE WHEN status = 'pending' THEN 0 WHEN status = 'approved' THEN 1 ELSE 2 END, created_at DESC";

          const { results: userRows } = await db
            .prepare(query)
            .bind(...params)
            .all();

          const { results: oauthRows } = await db
            .prepare(
              "SELECT id, username, provider, provider_user_id, email, display_name, created_at FROM user_oauth_accounts"
            )
            .all();

          const oauthByUser = new Map();
          for (const row of oauthRows || []) {
            const list = oauthByUser.get(row.username) || [];
            list.push({
              id: row.id,
              provider: row.provider,
              provider_user_id: row.provider_user_id,
              email: row.email,
              display_name: row.display_name,
              created_at: row.created_at,
            });
            oauthByUser.set(row.username, list);
          }

          const formattedUsers = (userRows || []).map((u) => ({
            id: u.id,
            username: u.username,
            email: u.email || null,
            role: isUserAdmin(u) ? "admin" : u.role || "user",
            status: u.status || "approved",
            totp_enabled: Boolean(u.totp_secret),
            oauth_accounts: oauthByUser.get(u.username) || [],
            created_at: u.created_at,
          }));

          const pendingCount = formattedUsers.filter((u) => u.status === "pending").length;

          return jsonResponse({
            pending_count: pendingCount,
            total_count: formattedUsers.length,
            users: formattedUsers,
          });
        }

        // 2. PATCH /api/admin/users (or /api/admin/users/:username) - Approve / Reject / Update Role
        if (request.method === "PATCH" || request.method === "PUT") {
          const pathUsername = url.pathname.startsWith("/api/admin/users/")
            ? decodeURIComponent(url.pathname.slice("/api/admin/users/".length))
            : null;
          const body = await request.json();
          const targetUsername = pathUsername || body.username;

          if (!targetUsername) {
            return jsonResponse(
              { error: "Missing required field: username" },
              { status: 400 }
            );
          }

          const existingUser = await db
            .prepare("SELECT * FROM users WHERE username = ?")
            .bind(targetUsername)
            .first();

          if (!existingUser) {
            return jsonResponse({ error: "User not found" }, { status: 404 });
          }

          const nextStatus = body.status || existingUser.status || "approved";
          if (!["pending", "approved", "rejected"].includes(nextStatus)) {
            return jsonResponse(
              { error: "Invalid status. Must be 'approved', 'pending', or 'rejected'" },
              { status: 400 }
            );
          }

          const nextRole = body.role || existingUser.role || "user";
          if (!["admin", "user"].includes(nextRole)) {
            return jsonResponse(
              { error: "Invalid role. Must be 'admin' or 'user'" },
              { status: 400 }
            );
          }

          // Clear session_token and user_sessions if account is rejected or moved back to pending
          const nextSessionToken =
            nextStatus === "approved" ? existingUser.session_token : null;

          await ensureSecurityTables(db);
          await db
            .prepare(
              "UPDATE users SET status = ?, role = ?, session_token = ?, failed_login_attempts = 0, locked_until = NULL WHERE username = ?"
            )
            .bind(nextStatus, nextRole, nextSessionToken, targetUsername)
            .run();

          if (nextStatus !== "approved") {
            await db
              .prepare("DELETE FROM user_sessions WHERE username = ?")
              .bind(targetUsername)
              .run();
          }

          let finalUsername = targetUsername;
          if (body.new_username && String(body.new_username).trim() !== targetUsername) {
            const renameResult = await renameUsernameInDb(
              db,
              targetUsername,
              body.new_username
            );
            if (renameResult.error) {
              return jsonResponse(
                { error: renameResult.error },
                { status: renameResult.status || 400 }
              );
            }
            finalUsername = renameResult.username;
            ctx.waitUntil(
              invalidateVisitCaches(cache, url.origin, [targetUsername, finalUsername])
            );
          }

          return jsonResponse({
            success: true,
            old_username: targetUsername,
            username: finalUsername,
            status: nextStatus,
            role: nextRole,
          });
        }

        // 3. DELETE /api/admin/users (or /api/admin/users/:username) - Remove a user
        if (request.method === "DELETE") {
          const pathUsername = url.pathname.startsWith("/api/admin/users/")
            ? decodeURIComponent(url.pathname.slice("/api/admin/users/".length))
            : null;
          let body = {};
          try {
            body = await request.json();
          } catch {
            // Optional JSON body
          }
          const targetUsername =
            pathUsername || url.searchParams.get("username") || body.username;

          if (!targetUsername) {
            return jsonResponse(
              { error: "Missing required field: username" },
              { status: 400 }
            );
          }

          if (user.username && targetUsername.toLowerCase() === user.username.toLowerCase()) {
            return jsonResponse(
              { error: "You cannot delete your own active admin account" },
              { status: 400 }
            );
          }

          await ensureSecurityTables(db);
          await db
            .prepare("DELETE FROM user_sessions WHERE username = ?")
            .bind(targetUsername)
            .run();
          await db
            .prepare("DELETE FROM user_api_keys WHERE username = ?")
            .bind(targetUsername)
            .run();
          await db
            .prepare("DELETE FROM user_oauth_accounts WHERE username = ?")
            .bind(targetUsername)
            .run();
          await db
            .prepare("DELETE FROM user_passkeys WHERE username = ?")
            .bind(targetUsername)
            .run();
          const info = await db
            .prepare("DELETE FROM users WHERE username = ?")
            .bind(targetUsername)
            .run();

          if (info.meta.changes === 0) {
            return jsonResponse({ error: "User not found" }, { status: 404 });
          }

          return jsonResponse({
            success: true,
            deleted: targetUsername,
          });
        }
      } catch (err) {
        return jsonResponse({ error: err.message }, { status: 500 });
      }
    }

    // =========================================================================
    // PATCH /api/user/username (or PATCH /api/user) - Edit current user's username (Protected)
    // =========================================================================
    if (
      (request.method === "PATCH" || request.method === "PUT") &&
      (url.pathname === "/api/user/username" || url.pathname === "/api/user")
    ) {
      const { user, errorResponse } = await authenticateRequest(request, env, db);
      if (errorResponse) return errorResponse;
      if (!user.username) {
        return jsonResponse(
          { error: "Please sign in with a user account to edit your username" },
          { status: 400 }
        );
      }

      try {
        const body = await request.json();
        const requestedUsername = body.new_username || body.username;

        const renameResult = await renameUsernameInDb(
          db,
          user.username,
          requestedUsername
        );
        if (renameResult.error) {
          return jsonResponse(
            { error: renameResult.error },
            { status: renameResult.status || 400 }
          );
        }

        if (renameResult.changed) {
          ctx.waitUntil(
            invalidateVisitCaches(cache, url.origin, [
              user.username,
              renameResult.username,
            ])
          );
        }

        return jsonResponse({
          success: true,
          old_username: user.username,
          username: renameResult.username,
        });
      } catch (err) {
        return jsonResponse({ error: err.message }, { status: 500 });
      }
    }

    // =========================================================================
    // PATCH or POST /api/user/password - Change or set password with PBKDF2-SHA256 (Protected)
    // =========================================================================
    if (
      (request.method === "PATCH" ||
        request.method === "PUT" ||
        request.method === "POST") &&
      url.pathname === "/api/user/password"
    ) {
      const { user, errorResponse } = await authenticateRequest(request, env, db);
      if (errorResponse) return errorResponse;
      if (!user.username) {
        return jsonResponse(
          { error: "Please sign in with a user account to change your password" },
          { status: 400 }
        );
      }

      try {
        const body = await request.json();
        const currentPassword = body.current_password || "";
        const newPassword = body.new_password || body.password || "";

        if (!newPassword || String(newPassword).length < 8) {
          return jsonResponse(
            { error: "New password must be at least 8 characters long" },
            { status: 400 }
          );
        }

        const userRow = await db
          .prepare("SELECT * FROM users WHERE username = ?")
          .bind(user.username)
          .first();

        if (!userRow) {
          return jsonResponse({ error: "User not found" }, { status: 404 });
        }

        // If user already has a password set, verify current_password before changing
        if (userRow.password && String(userRow.password).length > 0) {
          if (!currentPassword) {
            return jsonResponse(
              { error: "Current password is required to change your password" },
              { status: 400 }
            );
          }
          const validCurrent = await verifyUserPassword(
            db,
            userRow,
            currentPassword
          );
          if (!validCurrent) {
            return jsonResponse(
              { error: "Current password is incorrect" },
              { status: 401 }
            );
          }
        }

        const newPasswordHash = await hashPassword(newPassword);
        await db
          .prepare("UPDATE users SET password = ? WHERE username = ?")
          .bind(newPasswordHash, user.username)
          .run();

        // Optionally revoke all other sessions if revoke_other_sessions is requested
        if (body.revoke_other_sessions && user.currentSessionToken) {
          await ensureSecurityTables(db);
          await db
            .prepare(
              "DELETE FROM user_sessions WHERE username = ? AND token != ?"
            )
            .bind(user.username, user.currentSessionToken)
            .run();
        }

        return jsonResponse({
          success: true,
          has_password: true,
          message: "Password updated and hashed with PBKDF2-SHA256.",
        });
      } catch (err) {
        return jsonResponse({ error: err.message }, { status: 500 });
      }
    }

    // =========================================================================
    // GET & DELETE /api/sessions - Multi-Device Active Sessions Manager (Protected)
    // =========================================================================
    if (
      url.pathname === "/api/sessions" ||
      url.pathname.startsWith("/api/sessions/")
    ) {
      const { user, errorResponse } = await authenticateRequest(request, env, db);
      if (errorResponse) return errorResponse;
      if (!user.username) {
        return jsonResponse({ sessions: [] });
      }

      try {
        await ensureSecurityTables(db);
        const nowMs = Date.now();

        if (request.method === "GET") {
          await db
            .prepare("DELETE FROM user_sessions WHERE expires_at < ?")
            .bind(nowMs)
            .run();

          const { results } = await db
            .prepare(
              "SELECT id, token, user_agent, ip_address, created_at, last_used_at, expires_at FROM user_sessions WHERE username = ? ORDER BY last_used_at DESC, id DESC"
            )
            .bind(user.username)
            .all();

          const sessions = (results || []).map((s) => ({
            id: s.id,
            user_agent: s.user_agent || "Browser",
            ip_address: s.ip_address || null,
            created_at: s.created_at,
            last_used_at: s.last_used_at,
            expires_at: s.expires_at,
            is_current: Boolean(
              user.currentSessionToken && s.token === user.currentSessionToken
            ),
          }));

          return jsonResponse({
            username: user.username,
            sessions,
          });
        }

        if (request.method === "DELETE") {
          const pathId = url.pathname.startsWith("/api/sessions/")
            ? url.pathname.slice("/api/sessions/".length)
            : null;
          let body = {};
          try {
            body = await request.json();
          } catch {
            // Optional JSON body
          }

          const allOthers =
            url.searchParams.get("all_others") === "true" ||
            body.all_others === true;
          const sessionId = pathId || url.searchParams.get("id") || body.id;

          if (allOthers) {
            if (user.currentSessionToken) {
              await db
                .prepare(
                  "DELETE FROM user_sessions WHERE username = ? AND token != ?"
                )
                .bind(user.username, user.currentSessionToken)
                .run();
            } else {
              await db
                .prepare("DELETE FROM user_sessions WHERE username = ?")
                .bind(user.username)
                .run();
            }
            return jsonResponse({
              success: true,
              revoked: "all_others",
            });
          }

          if (!sessionId) {
            return jsonResponse(
              { error: "Specify session id or all_others=true to revoke" },
              { status: 400 }
            );
          }

          await db
            .prepare("DELETE FROM user_sessions WHERE username = ? AND id = ?")
            .bind(user.username, sessionId)
            .run();

          return jsonResponse({
            success: true,
            revoked_id: Number(sessionId),
          });
        }
      } catch (err) {
        return jsonResponse({ error: err.message }, { status: 500 });
      }
    }

    // =========================================================================
    // GET, POST & DELETE /api/api-keys - Personal Access Tokens / API Keys (Protected)
    // =========================================================================
    if (
      url.pathname === "/api/api-keys" ||
      url.pathname.startsWith("/api/api-keys/")
    ) {
      const { user, errorResponse } = await authenticateRequest(request, env, db);
      if (errorResponse) return errorResponse;
      if (!user.username) {
        return jsonResponse(
          { error: "Please sign in with a user account to manage API keys" },
          { status: 400 }
        );
      }

      try {
        await ensureSecurityTables(db);
        const nowMs = Date.now();

        if (request.method === "GET") {
          const { results } = await db
            .prepare(
              "SELECT id, label, key_prefix, created_at, last_used_at, expires_at FROM user_api_keys WHERE username = ? ORDER BY id DESC"
            )
            .bind(user.username)
            .all();

          const apiKeys = (results || []).map((k) => ({
            id: k.id,
            label: k.label,
            key_prefix: k.key_prefix,
            created_at: k.created_at,
            last_used_at: k.last_used_at || null,
            expires_at: k.expires_at || null,
            expired: Boolean(k.expires_at && Number(k.expires_at) < nowMs),
          }));

          return jsonResponse({
            username: user.username,
            api_keys: apiKeys,
          });
        }

        if (request.method === "POST") {
          const body = await request.json();
          const label = String(body.label || "Personal Access Token").trim();
          const expiresInDays = body.expires_in_days
            ? parseInt(body.expires_in_days, 10)
            : null;
          const expiresAt =
            expiresInDays && Number.isFinite(expiresInDays) && expiresInDays > 0
              ? nowMs + expiresInDays * 24 * 60 * 60 * 1000
              : null;

          const rawKey = `atk_${bytesToBase64Url(
            crypto.getRandomValues(new Uint8Array(32))
          )}`;
          const keyPrefix = `${rawKey.slice(0, 12)}...`;
          const keyHash = await sha256Hex(rawKey);

          const info = await db
            .prepare(
              `INSERT INTO user_api_keys (username, label, key_prefix, key_hash, expires_at)
               VALUES (?, ?, ?, ?, ?)`
            )
            .bind(user.username, label, keyPrefix, keyHash, expiresAt)
            .run();

          return jsonResponse(
            {
              success: true,
              api_key: rawKey,
              key: {
                id: info.meta?.last_row_id || null,
                label,
                key_prefix: keyPrefix,
                expires_at: expiresAt,
              },
              message:
                "Copy this API key now. For security, only its SHA-256 hash is stored and it cannot be viewed again.",
            },
            { status: 201 }
          );
        }

        if (request.method === "DELETE") {
          const pathId = url.pathname.startsWith("/api/api-keys/")
            ? url.pathname.slice("/api/api-keys/".length)
            : null;
          let body = {};
          try {
            body = await request.json();
          } catch {
            // Optional JSON body
          }
          const keyId = pathId || url.searchParams.get("id") || body.id;

          if (!keyId) {
            return jsonResponse(
              { error: "Missing required field: id" },
              { status: 400 }
            );
          }

          await db
            .prepare("DELETE FROM user_api_keys WHERE username = ? AND id = ?")
            .bind(user.username, keyId)
            .run();

          return jsonResponse({
            success: true,
            revoked_id: Number(keyId),
          });
        }
      } catch (err) {
        return jsonResponse({ error: err.message }, { status: 500 });
      }
    }

    // =========================================================================
    // POST /api/logout - Clear active session token
    // =========================================================================
    if (request.method === "POST" && url.pathname === "/api/logout") {
      try {
        const authHeader = request.headers.get("Authorization");
        if (authHeader && authHeader.startsWith("Bearer ")) {
          const token = authHeader.slice("Bearer ".length).trim();
          if (token) {
            try {
              await ensureSecurityTables(db);
              await db
                .prepare("DELETE FROM user_sessions WHERE token = ?")
                .bind(token)
                .run();
            } catch {
              // Ignore if user_sessions not initialized
            }
            await db
              .prepare("UPDATE users SET session_token = NULL WHERE session_token = ?")
              .bind(token)
              .run();
          }
        }
        return jsonResponse({ success: true });
      } catch (err) {
        return jsonResponse({ error: err.message }, { status: 500 });
      }
    }

    // =========================================================================
    // GET /api/2fa/status - Check enabled 2FA methods & passkeys for current user (Protected)
    // =========================================================================
    if (request.method === "GET" && url.pathname === "/api/2fa/status") {
      const { user, errorResponse } = await authenticateRequest(request, env, db);
      if (errorResponse) return errorResponse;
      if (!user.username) {
        return jsonResponse({ totp_enabled: false, webauthn_enabled: false, passkeys: [] });
      }

      try {
        const record = await db
          .prepare("SELECT * FROM users WHERE username = ?")
          .bind(user.username)
          .first();

        const passkeys = await getUserPasskeys(db, user.username);
        const oauthAccounts = await getUserOAuthAccounts(db, user.username);
        const adminFlag = isUserAdmin(record || user);

        return jsonResponse({
          username: user.username,
          role: adminFlag ? "admin" : (record && record.role) || "user",
          is_admin: adminFlag,
          status: (record && record.status) || "approved",
          has_password: Boolean(record && record.password),
          totp_enabled: Boolean(record && record.totp_secret),
          webauthn_enabled: passkeys.length > 0,
          passkey_count: passkeys.length,
          passkeys: passkeys.map((k, idx) => ({
            id: k.id,
            credential_id: k.credential_id,
            label: k.label || `Security Key #${idx + 1}`,
            created_at: k.created_at,
          })),
          oauth_accounts: oauthAccounts,
        });
      } catch (err) {
        return jsonResponse({ error: err.message }, { status: 500 });
      }
    }

    // =========================================================================
    // POST /api/2fa/totp/setup - Generate pending Base32 TOTP secret (Protected)
    // =========================================================================
    if (request.method === "POST" && url.pathname === "/api/2fa/totp/setup") {
      const { user, errorResponse } = await authenticateRequest(request, env, db);
      if (errorResponse) return errorResponse;
      if (!user.username) {
        return jsonResponse(
          { error: "Please sign in with a user account to set up 2FA" },
          { status: 400 }
        );
      }

      try {
        const secret = generateBase32Secret(20);
        try {
          // Save to totp_pending_secret so the user is not locked out until they verify a 6-digit code
          await db
            .prepare("UPDATE users SET totp_pending_secret = ? WHERE username = ?")
            .bind(secret, user.username)
            .run();
        } catch {
          // Fallback if totp_pending_secret column wasn't added yet
          await db
            .prepare("UPDATE users SET totp_secret = ? WHERE username = ?")
            .bind(secret, user.username)
            .run();
        }

        const otpauthUrl = `otpauth://totp/AirportTracker:${encodeURIComponent(
          user.username
        )}?secret=${secret}&issuer=AirportTracker`;

        return jsonResponse({
          success: true,
          secret,
          otpauth_url: otpauthUrl,
          pending_verification: true,
        });
      } catch (err) {
        return jsonResponse({ error: err.message }, { status: 500 });
      }
    }

    // =========================================================================
    // POST /api/2fa/totp/verify - Verify 6-digit code & activate TOTP 2FA (Protected)
    // =========================================================================
    if (request.method === "POST" && url.pathname === "/api/2fa/totp/verify") {
      const { user, errorResponse } = await authenticateRequest(request, env, db);
      if (errorResponse) return errorResponse;
      if (!user.username) {
        return jsonResponse(
          { error: "Please sign in with a user account to verify 2FA" },
          { status: 400 }
        );
      }

      try {
        const body = await request.json();
        const code = body.code || body.totp_code;
        if (!code) {
          return jsonResponse(
            { error: "Please enter the 6-digit code from your Authenticator app" },
            { status: 400 }
          );
        }

        let record;
        try {
          record = await db
            .prepare(
              "SELECT totp_pending_secret, totp_secret FROM users WHERE username = ?"
            )
            .bind(user.username)
            .first();
        } catch {
          record = await db
            .prepare("SELECT totp_secret FROM users WHERE username = ?")
            .bind(user.username)
            .first();
        }

        const candidateSecret =
          (record && record.totp_pending_secret) || (record && record.totp_secret);
        if (!candidateSecret) {
          return jsonResponse(
            { error: "No pending Authenticator setup found. Click Setup first." },
            { status: 400 }
          );
        }

        const isValid = await verifyTotp(candidateSecret, code);
        if (!isValid) {
          return jsonResponse(
            { error: "Invalid 6-digit code. Check your Authenticator app and try again." },
            { status: 400 }
          );
        }

        try {
          await db
            .prepare(
              "UPDATE users SET totp_secret = ?, totp_pending_secret = NULL WHERE username = ?"
            )
            .bind(candidateSecret, user.username)
            .run();
        } catch {
          await db
            .prepare("UPDATE users SET totp_secret = ? WHERE username = ?")
            .bind(candidateSecret, user.username)
            .run();
        }

        return jsonResponse({
          success: true,
          totp_enabled: true,
        });
      } catch (err) {
        return jsonResponse({ error: err.message }, { status: 500 });
      }
    }

    // =========================================================================
    // DELETE /api/2fa/totp, DELETE /api/webauthn, DELETE /api/2fa - Remove 2FA (Protected)
    // =========================================================================
    if (
      (request.method === "DELETE" &&
        (url.pathname === "/api/2fa/totp" ||
          url.pathname === "/api/2fa/webauthn" ||
          url.pathname === "/api/webauthn" ||
          url.pathname === "/api/2fa")) ||
      (request.method === "POST" && url.pathname === "/api/2fa/totp/disable")
    ) {
      const { user, errorResponse } = await authenticateRequest(request, env, db);
      if (errorResponse) return errorResponse;
      if (!user.username) {
        return jsonResponse(
          { error: "Please sign in with a user account to manage 2FA" },
          { status: 400 }
        );
      }

      try {
        let targetType = "all";
        let bodyData = null;
        try {
          bodyData = await request.json();
        } catch {
          // Optional JSON body
        }

        if (url.pathname === "/api/2fa/totp" || url.pathname === "/api/2fa/totp/disable") {
          targetType = "totp";
        } else if (url.pathname === "/api/2fa/webauthn" || url.pathname === "/api/webauthn") {
          targetType = "webauthn";
        } else if (bodyData && bodyData.type) {
          targetType = bodyData.type;
        }

        if (targetType === "totp") {
          try {
            await db
              .prepare(
                "UPDATE users SET totp_secret = NULL, totp_pending_secret = NULL WHERE username = ?"
              )
              .bind(user.username)
              .run();
          } catch {
            await db
              .prepare("UPDATE users SET totp_secret = NULL WHERE username = ?")
              .bind(user.username)
              .run();
          }
        } else if (targetType === "webauthn") {
          const credentialIdToDelete =
            url.searchParams.get("credential_id") ||
            (bodyData && bodyData.credential_id) ||
            null;
          await getUserPasskeys(db, user.username);
          if (credentialIdToDelete) {
            await db
              .prepare(
                "DELETE FROM user_passkeys WHERE username = ? AND credential_id = ?"
              )
              .bind(user.username, credentialIdToDelete)
              .run();
          } else {
            await db
              .prepare("DELETE FROM user_passkeys WHERE username = ?")
              .bind(user.username)
              .run();
            await db
              .prepare(
                "UPDATE users SET webauthn_challenge = NULL WHERE username = ?"
              )
              .bind(user.username)
              .run();
          }
        } else {
          await getUserPasskeys(db, user.username);
          await db
            .prepare("DELETE FROM user_passkeys WHERE username = ?")
            .bind(user.username)
            .run();
          try {
            await db
              .prepare(
                "UPDATE users SET totp_secret = NULL, totp_pending_secret = NULL, webauthn_challenge = NULL WHERE username = ?"
              )
              .bind(user.username)
              .run();
          } catch {
            await db
              .prepare(
                "UPDATE users SET totp_secret = NULL, webauthn_challenge = NULL WHERE username = ?"
              )
              .bind(user.username)
              .run();
          }
        }

        return jsonResponse({
          success: true,
          disabled: targetType,
        });
      } catch (err) {
        return jsonResponse({ error: err.message }, { status: 500 });
      }
    }

    // =========================================================================
    // POST /api/webauthn/register-options - Start YubiKey / Passkey enrollment (Protected)
    // =========================================================================
    if (request.method === "POST" && url.pathname === "/api/webauthn/register-options") {
      const { user, errorResponse } = await authenticateRequest(request, env, db);
      if (errorResponse) return errorResponse;
      if (!user.username) {
        return jsonResponse(
          { error: "Please sign in with a user account to register a security key" },
          { status: 400 }
        );
      }

      try {
        const challenge = bytesToBase64Url(crypto.getRandomValues(new Uint8Array(32)));
        await db
          .prepare("UPDATE users SET webauthn_challenge = ? WHERE username = ?")
          .bind(challenge, user.username)
          .run();

        const existingKeys = await getUserPasskeys(db, user.username);

        return jsonResponse({
          challenge,
          rpId: getRpId(request, url),
          pubKeyCredParams: [
            { alg: -7, type: "public-key" },
            { alg: -257, type: "public-key" },
          ],
          excludeCredentials: existingKeys.map((k) => ({
            id: k.credential_id,
            type: "public-key",
          })),
        });
      } catch (err) {
        return jsonResponse({ error: err.message }, { status: 500 });
      }
    }

    // =========================================================================
    // PATCH /api/webauthn/edit-options - Edit label for a registered YubiKey / Passkey (Protected)
    // =========================================================================
    if (request.method === "PATCH" && url.pathname === "/api/webauthn/edit-options") {
      const { user, errorResponse } = await authenticateRequest(request, env, db);
      if (errorResponse) return errorResponse;
      if (!user.username) {
        return jsonResponse(
          { error: "Please sign in with a user account to edit a security key" },
          { status: 400 }
        );
      }

      try {
        const { credential_id, label } = await request.json();
        if (!credential_id || !label) {
          return jsonResponse(
            { error: "Missing required fields: credential_id and label" },
            { status: 400 }
          );
        }

        const result = await db
          .prepare(
            "UPDATE user_passkeys SET label = ? WHERE username = ? AND credential_id = ?"
          )
          .bind(label, user.username, credential_id)
          .run();

        if (result.changes === 0) {
          return jsonResponse(
            { error: "No matching security key found for this user" },
            { status: 404 }
          );
        }

        return jsonResponse({
          success: true,
          updated: { credential_id, label },
        });
      } catch (err) {
        return jsonResponse({ error: err.message }, { status: 500 });
      }
    }

    // =========================================================================
    // POST /api/webauthn/register-verify - Save YubiKey credential_id & SPKI public_key (Protected)
    // =========================================================================
    if (request.method === "POST" && url.pathname === "/api/webauthn/register-verify") {
      const { user, errorResponse } = await authenticateRequest(request, env, db);
      if (errorResponse) return errorResponse;
      if (!user.username) {
        return jsonResponse(
          { error: "Please sign in with a user account to register a security key" },
          { status: 400 }
        );
      }

      try {
        const { credential_id, public_key, label } = await request.json();
        if (!credential_id || !public_key) {
          return jsonResponse(
            { error: "Missing required fields: credential_id and public_key" },
            { status: 400 }
          );
        }

        const existingKeys = await getUserPasskeys(db, user.username);
        const keyLabel = label || `Security Key #${existingKeys.length + 1}`;

        await db
          .prepare(
            `INSERT INTO user_passkeys (username, credential_id, public_key, label)
             VALUES (?, ?, ?, ?)
             ON CONFLICT(credential_id) DO UPDATE SET
               public_key = excluded.public_key,
               label = COALESCE(excluded.label, user_passkeys.label)`
          )
          .bind(user.username, credential_id, public_key, keyLabel)
          .run();

        await db
          .prepare("UPDATE users SET webauthn_challenge = NULL WHERE username = ?")
          .bind(user.username)
          .run();

        const updatedKeys = await getUserPasskeys(db, user.username);

        return jsonResponse({
          success: true,
          passkey_count: updatedKeys.length,
        });
      } catch (err) {
        return jsonResponse({ error: err.message }, { status: 500 });
      }
    }

    // =========================================================================
    // POST /api/webauthn/login-options - Issue challenge for YubiKey / Passkey sign-in
    // =========================================================================
    if (request.method === "POST" && url.pathname === "/api/webauthn/login-options") {
      try {
        const { username, password } = await request.json();
        if (!username) {
          return jsonResponse({ error: "Username is required" }, { status: 400 });
        }

        const user = await db
          .prepare("SELECT username, password FROM users WHERE username = ?")
          .bind(username)
          .first();

        if (!user) {
          return jsonResponse(
            { error: "No YubiKey or security key registered for this user" },
            { status: 400 }
          );
        }

        const passkeys = await getUserPasskeys(db, user.username);
        if (passkeys.length === 0) {
          return jsonResponse(
            { error: "No YubiKey or security key registered for this user" },
            { status: 400 }
          );
        }

        // If password was also supplied by the user, verify it matches (supporting PBKDF2 hash & legacy plaintext)
        if (password !== undefined && password !== "") {
          const validPw = await verifyUserPassword(db, user, password);
          if (!validPw) {
            await recordFailedLoginAttempt(db, user);
            return jsonResponse({ error: "Invalid username or password" }, { status: 401 });
          }
        }

        const challenge = bytesToBase64Url(crypto.getRandomValues(new Uint8Array(32)));
        await db
          .prepare("UPDATE users SET webauthn_challenge = ? WHERE username = ?")
          .bind(challenge, user.username)
          .run();

        return jsonResponse({
          challenge,
          rpId: getRpId(request, url),
          allowCredentials: passkeys.map((k) => ({
            id: k.credential_id,
            type: "public-key",
            transports: ["usb", "nfc", "ble", "internal", "hybrid"],
          })),
        });
      } catch (err) {
        return jsonResponse({ error: err.message }, { status: 500 });
      }
    }

    // =========================================================================
    // POST /api/webauthn/login-verify - Verify YubiKey / Passkey signature & issue session token
    // =========================================================================
    if (request.method === "POST" && url.pathname === "/api/webauthn/login-verify") {
      try {
        const {
          username,
          credential_id,
          authenticator_data,
          client_data_json,
          signature,
        } = await request.json();

        if (
          !username ||
          !credential_id ||
          !authenticator_data ||
          !client_data_json ||
          !signature
        ) {
          return jsonResponse(
            { error: "Missing required WebAuthn assertion fields" },
            { status: 400 }
          );
        }

        const user = await db
          .prepare("SELECT * FROM users WHERE username = ?")
          .bind(username)
          .first();

        if (!user || !user.webauthn_challenge) {
          return jsonResponse(
            { error: "Invalid security key login state" },
            { status: 401 }
          );
        }

        const passkeys = await getUserPasskeys(db, user.username);
        const matchedKey = passkeys.find((k) => k.credential_id === credential_id);
        if (!matchedKey || !matchedKey.public_key) {
          return jsonResponse(
            { error: "Unrecognized security key or passkey for this user" },
            { status: 401 }
          );
        }

        const clientDataBytes = base64UrlToBytes(client_data_json);
        const clientData = JSON.parse(new TextDecoder().decode(clientDataBytes));
        if (clientData.challenge !== user.webauthn_challenge) {
          return jsonResponse({ error: "Challenge mismatch" }, { status: 401 });
        }

        const authDataBytes = base64UrlToBytes(authenticator_data);
        const clientDataHash = new Uint8Array(
          await crypto.subtle.digest("SHA-256", clientDataBytes)
        );
        const signedData = new Uint8Array(authDataBytes.length + clientDataHash.length);
        signedData.set(authDataBytes, 0);
        signedData.set(clientDataHash, authDataBytes.length);

        const spkiBytes = base64UrlToBytes(matchedKey.public_key);
        const sigBytes = base64UrlToBytes(signature);
        let isValid = false;

        try {
          // 1. Try ES256 (ECDSA P-256, alg: -7)
          const ecKey = await crypto.subtle.importKey(
            "spki",
            spkiBytes,
            { name: "ECDSA", namedCurve: "P-256" },
            false,
            ["verify"]
          );
          isValid = await crypto.subtle.verify(
            { name: "ECDSA", hash: "SHA-256" },
            ecKey,
            derToP1363Signature(sigBytes),
            signedData
          );
        } catch {
          // 2. Fallback to RS256 (RSASSA-PKCS1-v1_5 SHA-256, alg: -257)
          const rsaKey = await crypto.subtle.importKey(
            "spki",
            spkiBytes,
            { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
            false,
            ["verify"]
          );
          isValid = await crypto.subtle.verify(
            { name: "RSASSA-PKCS1-v1_5" },
            rsaKey,
            sigBytes,
            signedData
          );
        }

        if (!isValid) {
          await recordFailedLoginAttempt(db, user);
          return jsonResponse(
            { error: "Security key signature verification failed" },
            { status: 401 }
          );
        }

        const lockoutResponse = checkAccountLockout(user);
        if (lockoutResponse) return lockoutResponse;

        const accountStatus = user.status || "approved";
        if (accountStatus !== "approved") {
          return jsonResponse(
            {
              error:
                accountStatus === "pending"
                  ? "Your account is awaiting admin approval before you can sign in."
                  : "Your account request was not approved.",
              status: accountStatus,
              pending_approval: accountStatus === "pending",
            },
            { status: 403 }
          );
        }

        await clearFailedLoginAttempts(db, user.username);
        await db
          .prepare("UPDATE users SET webauthn_challenge = NULL WHERE username = ?")
          .bind(user.username)
          .run();
        const session = await createUserSession(db, request, user.username);

        const adminFlag = isUserAdmin(user);
        return jsonResponse({
          success: true,
          token: session.token,
          expires_at: session.expires_at,
          username: user.username,
          role: adminFlag ? "admin" : user.role || "user",
          is_admin: adminFlag,
          status: accountStatus,
        });
      } catch (err) {
        return jsonResponse({ error: err.message }, { status: 500 });
      }
    }

    // =========================================================================
    // GET /api/visits - Public read access (with airport metadata join)
    // =========================================================================
    if (request.method === "GET" && url.pathname === "/api/visits") {
      try {
        const cached = await cache.match(request);
        if (cached) return cached;

        const username = url.searchParams.get("username");
        const limitParam = parseInt(url.searchParams.get("limit") || "100", 10);
        const limit = Number.isFinite(limitParam) ? Math.min(Math.max(limitParam, 1), 500) : 100;
        const beforeDate = url.searchParams.get("before");

        const conditions = [];
        const params = [];

        if (username) {
          conditions.push("v.username = ?");
          params.push(username);
        }
        if (beforeDate) {
          conditions.push("v.visit_date < ?");
          params.push(beforeDate);
        }
        const whereClause = conditions.length > 0 ? ` WHERE ${conditions.join(" AND ")}` : "";
        params.push(limit);

        let results;
        try {
          try {
            await db
              .prepare("ALTER TABLE airport_visits ADD COLUMN destination_iata TEXT")
              .run();
          } catch {
            // Column already exists
          }

          const query = `
            SELECT
              v.id,
              v.iata_code,
              COALESCE(v.airport_name, a.name) AS airport_name,
              v.visit_date,
              v.username,
              v.notes,
              v.origin_iata,
              COALESCE(v.destination_iata, v.iata_code) AS destination_iata,
              v.flight_number,
              v.distance_km,
              a.city,
              a.country,
              a.latitude,
              a.longitude
            FROM airport_visits v
            LEFT JOIN airports a ON v.iata_code = a.iata_code
            ${whereClause}
            ORDER BY v.visit_date DESC
            LIMIT ?
          `;
          ({ results } = await db.prepare(query).bind(...params).all());
        } catch {
          // Fallback if 0003 migration has not been run yet
          const fallbackQuery = `
            SELECT id, iata_code, airport_name, visit_date, username, notes
            FROM airport_visits v
            ${whereClause}
            ORDER BY v.visit_date DESC
            LIMIT ?
          `;
          ({ results } = await db.prepare(fallbackQuery).bind(...params).all());
        }

        const response = Response.json(results, { headers: cacheHeaders() });
        ctx.waitUntil(cache.put(request, response.clone()));
        return response;
      } catch (err) {
        return jsonResponse({ error: err.message }, { status: 500 });
      }
    }

    // =========================================================================
    // GET /api/visits/airports - Public read access (visited airports list)
    // =========================================================================
    if (request.method === "GET" && url.pathname === "/api/visits/airports") {
      try {
        const cached = await cache.match(request);
        if (cached) return cached;

        const username = url.searchParams.get("username");
        const distinct = url.searchParams.get("distinct") === "true";

        let query = distinct
          ? "SELECT iata_code, MAX(visit_date) AS last_visit_date, COUNT(*) AS visit_count FROM airport_visits"
          : "SELECT iata_code FROM airport_visits";
        const params = [];

        if (username) {
          query += " WHERE username = ?";
          params.push(username);
        }

        if (distinct) {
          query += " GROUP BY iata_code ORDER BY last_visit_date DESC";
        } else {
          query += " ORDER BY visit_date DESC";
        }

        const { results } = await db.prepare(query).bind(...params).all();
        const response = Response.json(results, { headers: cacheHeaders() });

        ctx.waitUntil(cache.put(request, response.clone()));
        return response;
      } catch (err) {
        return jsonResponse({ error: err.message }, { status: 500 });
      }
    }

    // =========================================================================
    // GET /api/stats - Travel stats & total distance flown (uses db.batch)
    // =========================================================================
    if (request.method === "GET" && url.pathname === "/api/stats") {
      try {
        const cached = await cache.match(request);
        if (cached) return cached;

        const username = url.searchParams.get("username");
        const whereClause = username ? "WHERE v.username = ?" : "";
        const bindParams = username ? [username] : [];

        const summaryStmt = db
          .prepare(
            `SELECT
              COUNT(*) AS total_visits,
              COUNT(DISTINCT v.iata_code) AS unique_airports,
              COUNT(DISTINCT a.country) AS unique_countries,
              MIN(v.visit_date) AS first_visit_date,
              MAX(v.visit_date) AS last_visit_date
            FROM airport_visits v
            LEFT JOIN airports a ON v.iata_code = a.iata_code
            ${whereClause}`
          )
          .bind(...bindParams);

        const topAirportsStmt = db
          .prepare(
            `SELECT
              v.iata_code,
              COALESCE(MAX(v.airport_name), a.name) AS airport_name,
              a.city,
              a.country,
              COUNT(*) AS visit_count
            FROM airport_visits v
            LEFT JOIN airports a ON v.iata_code = a.iata_code
            ${whereClause}
            GROUP BY v.iata_code
            ORDER BY visit_count DESC, MAX(v.visit_date) DESC
            LIMIT 10`
          )
          .bind(...bindParams);

        const countriesStmt = db
          .prepare(
            `SELECT
              a.country,
              COUNT(*) AS visit_count,
              COUNT(DISTINCT v.iata_code) AS unique_airports
            FROM airport_visits v
            INNER JOIN airports a ON v.iata_code = a.iata_code
            ${whereClause}
            GROUP BY a.country
            ORDER BY visit_count DESC`
          )
          .bind(...bindParams);

        const byYearStmt = db
          .prepare(
            `SELECT
              SUBSTR(v.visit_date, 1, 4) AS year,
              COUNT(*) AS visit_count,
              COUNT(DISTINCT v.iata_code) AS unique_airports
            FROM airport_visits v
            ${whereClause}
            GROUP BY year
            ORDER BY year DESC`
          )
          .bind(...bindParams);

        const flightsStmt = db
          .prepare(
            `SELECT
              v.iata_code,
              v.origin_iata,
              v.distance_km,
              a.latitude AS dest_lat,
              a.longitude AS dest_lon,
              orig.latitude AS orig_lat,
              orig.longitude AS orig_lon
            FROM airport_visits v
            LEFT JOIN airports a ON v.iata_code = a.iata_code
            LEFT JOIN airports orig ON v.origin_iata = orig.iata_code
            ${whereClause}
            ORDER BY v.visit_date ASC, v.id ASC`
          )
          .bind(...bindParams);

        // Execute all 5 analytical queries in a single D1 round-trip using db.batch()
        const [summaryRes, topAirportsRes, countriesRes, byYearRes, flightsRes] = await db.batch([
          summaryStmt,
          topAirportsStmt,
          countriesStmt,
          byYearStmt,
          flightsStmt,
        ]);

        // Calculate total distance flown (explicit origin->dest legs + sequential visits fallback)
        let totalDistanceKm = 0;
        let prevAirport = null;
        for (const leg of flightsRes.results || []) {
          let legKm = leg.distance_km;
          if (legKm == null && leg.orig_lat != null && leg.dest_lat != null) {
            legKm = calculateDistanceKm(leg.orig_lat, leg.orig_lon, leg.dest_lat, leg.dest_lon);
          } else if (
            legKm == null &&
            !leg.origin_iata &&
            prevAirport &&
            prevAirport.iata_code !== leg.iata_code &&
            prevAirport.dest_lat != null &&
            leg.dest_lat != null
          ) {
            legKm = calculateDistanceKm(
              prevAirport.dest_lat,
              prevAirport.dest_lon,
              leg.dest_lat,
              leg.dest_lon
            );
          }
          if (legKm != null) {
            totalDistanceKm += Number(legKm);
          }
          prevAirport = leg;
        }

        totalDistanceKm = Math.round(totalDistanceKm * 10) / 10;
        const totalDistanceMiles = Math.round(totalDistanceKm * KM_TO_MILES * 10) / 10;
        const summary = (summaryRes.results && summaryRes.results[0]) || {};

        const statsPayload = {
          username: username || "all",
          total_visits: summary.total_visits || 0,
          unique_airports: summary.unique_airports || 0,
          unique_countries: summary.unique_countries || 0,
          first_visit_date: summary.first_visit_date || null,
          last_visit_date: summary.last_visit_date || null,
          total_distance_km: totalDistanceKm,
          total_distance_miles: totalDistanceMiles,
          most_visited_airports: topAirportsRes.results || [],
          countries_visited: countriesRes.results || [],
          visits_by_year: byYearRes.results || [],
        };

        const response = Response.json(statsPayload, { headers: cacheHeaders() });
        ctx.waitUntil(cache.put(request, response.clone()));
        return response;
      } catch (err) {
        return jsonResponse({ error: err.message }, { status: 500 });
      }
    }

    // =========================================================================
    // GET /api/flights - Lookup origin & destination IATA by flight number (?flight_number=BA968)
    // =========================================================================
    if (
      request.method === "GET" &&
      (url.pathname === "/api/flights" || url.pathname.startsWith("/api/flights/"))
    ) {
      try {
        const pathFlight = url.pathname.startsWith("/api/flights/")
          ? decodeURIComponent(url.pathname.slice("/api/flights/".length))
          : null;
        const flightNumber =
          pathFlight ||
          url.searchParams.get("flight_number") ||
          url.searchParams.get("flight") ||
          url.searchParams.get("callsign");

        if (!flightNumber) {
          return jsonResponse(
            { error: "Provide a flight_number query parameter (e.g. ?flight_number=BA968)" },
            { status: 400 }
          );
        }

        const route = await resolveFlightRoute(db, flightNumber);
        if (!route) {
          return jsonResponse(
            {
              error: `Could not resolve route for flight '${String(flightNumber).toUpperCase()}'`,
            },
            { status: 404 }
          );
        }

        return jsonResponse(route);
      } catch (err) {
        return jsonResponse({ error: err.message }, { status: 500 });
      }
    }

    // =========================================================================
    // GET /api/airports - Reference table lookup (?code=LHR, ?search=London, or ?lat=51.47&lon=-0.45)
    // =========================================================================
    if (request.method === "GET" && url.pathname === "/api/airports") {
      try {
        const cached = await cache.match(request);
        if (cached) return cached;

        const code = url.searchParams.get("code");
        const search = url.searchParams.get("search");
        const latParam =
          url.searchParams.get("lat") ?? url.searchParams.get("latitude");
        const lonParam =
          url.searchParams.get("lon") ??
          url.searchParams.get("lng") ??
          url.searchParams.get("longitude");

        if (latParam != null && lonParam != null && latParam !== "" && lonParam !== "") {
          const limitParam = parseInt(url.searchParams.get("limit") || "5", 10) || 5;
          const maxKmParam = url.searchParams.get("max_km")
            ? Number(url.searchParams.get("max_km"))
            : null;
          let nearest = await findNearestAirports(db, latParam, lonParam, limitParam);
          if (maxKmParam != null && Number.isFinite(maxKmParam)) {
            nearest = nearest.filter((a) => a.distance_from_location_km <= maxKmParam);
          }
          const response = Response.json(nearest, { headers: cacheHeaders() });
          ctx.waitUntil(cache.put(request, response.clone()));
          return response;
        }

        let query = "SELECT iata_code, name, city, country, latitude, longitude FROM airports";
        const params = [];

        if (code) {
          query += " WHERE iata_code = ?";
          params.push(code.trim().toUpperCase());
        } else if (search) {
          const pattern = `%${search.trim().slice(0, 40)}%`;
          query += " WHERE iata_code LIKE ? OR name LIKE ? OR city LIKE ? OR country LIKE ?";
          params.push(pattern, pattern, pattern, pattern);
        }

        query += " ORDER BY iata_code ASC LIMIT 200";

        const { results } = await db.prepare(query).bind(...params).all();
        const response = Response.json(results, { headers: cacheHeaders() });
        ctx.waitUntil(cache.put(request, response.clone()));
        return response;
      } catch (err) {
        return jsonResponse({ error: err.message }, { status: 500 });
      }
    }

    // =========================================================================
    // POST /api/airports - Add or batch-upsert reference airports (Protected)
    // =========================================================================
    if (request.method === "POST" && url.pathname === "/api/airports") {
      const { errorResponse } = await authenticateRequest(request, env, db);
      if (errorResponse) return errorResponse;

      try {
        const body = await request.json();
        const items = Array.isArray(body) ? body : Array.isArray(body.airports) ? body.airports : [body];

        if (items.length === 0) {
          return jsonResponse({ error: "No airport records provided" }, { status: 400 });
        }

        const stmt = db.prepare(
          `INSERT INTO airports (iata_code, name, city, country, latitude, longitude)
           VALUES (?, ?, ?, ?, ?, ?)
           ON CONFLICT(iata_code) DO UPDATE SET
             name = excluded.name,
             city = COALESCE(excluded.city, airports.city),
             country = COALESCE(excluded.country, airports.country),
             latitude = excluded.latitude,
             longitude = excluded.longitude`
        );

        const batchStatements = [];
        for (const item of items) {
          if (!item.iata_code || !item.name || item.latitude == null || item.longitude == null) {
            return jsonResponse(
              { error: "Each airport requires iata_code, name, latitude, and longitude" },
              { status: 400 }
            );
          }
          batchStatements.push(
            stmt.bind(
              String(item.iata_code).trim().toUpperCase(),
              item.name,
              item.city || null,
              item.country || null,
              Number(item.latitude),
              Number(item.longitude)
            )
          );
        }

        const results = await db.batch(batchStatements);
        const totalChanges = results.reduce((acc, r) => acc + (r.meta?.changes || 0), 0);

        ctx.waitUntil(cache.delete(`${url.origin}/api/airports`));
        return jsonResponse({ success: true, count: batchStatements.length, changes: totalChanges });
      } catch (err) {
        return jsonResponse({ error: err.message }, { status: 500 });
      }
    }

    // =========================================================================
    // POST /api/visits - Single visit insert (Protected by session_token)
    // =========================================================================
    if (request.method === "POST" && url.pathname === "/api/visits") {
      const { user, errorResponse } = await authenticateRequest(request, env, db);
      if (errorResponse) return errorResponse;

      try {
        const body = await request.json();
        const { iata_code, airport_name, visit_date, notes, origin_iata, flight_number } = body;
        const rawLat = body.latitude ?? body.lat ?? null;
        const rawLon = body.longitude ?? body.lon ?? body.lng ?? null;
        const gpsLat =
          rawLat != null && rawLat !== ""
            ? Number(String(rawLat).trim().replace(",", "."))
            : null;
        const gpsLon =
          rawLon != null && rawLon !== ""
            ? Number(String(rawLon).trim().replace(",", "."))
            : null;
        const hasGps =
          gpsLat != null &&
          gpsLon != null &&
          Number.isFinite(gpsLat) &&
          Number.isFinite(gpsLon);

        // Automatically use the authenticated user's username (fallback to body.username for API_SECRET)
        const username = user.username || body.username || null;

        // Default visit_date to today's ISO date (`YYYY-MM-DD`) whenever omitted or empty
        const resolvedVisitDate =
          (visit_date && String(visit_date).trim()) ||
          new Date().toISOString().slice(0, 10);

        let visitedCode = iata_code ? String(iata_code).trim().toUpperCase() : "";
        let flightDestCode = body.destination_iata
          ? String(body.destination_iata).trim().toUpperCase()
          : "";
        let gpsDetectedCode = "";
        let detectedFromGps = false;
        let gpsDistanceKm = null;

        // 1. If GPS coordinates are provided and iata_code wasn't explicitly typed, the GPS airport IS the visited airport!
        if (hasGps && !visitedCode) {
          const maxRadiusKm =
            body.max_distance_km != null && Number.isFinite(Number(body.max_distance_km))
              ? Number(body.max_distance_km)
              : 35;
          const nearestList = await findNearestAirports(db, gpsLat, gpsLon, 1);
          const closest = nearestList[0];

          if (!closest) {
            return jsonResponse(
              { error: "No airports found in reference database for GPS lookup" },
              { status: 400 }
            );
          }

          if (closest.distance_from_location_km > maxRadiusKm) {
            return jsonResponse(
              {
                error: `No airport found within ${maxRadiusKm} km of your GPS coordinates. Closest airport is ${closest.name} (${closest.iata_code}) at ${closest.distance_from_location_km} km away.`,
                closest_airport: closest,
              },
              { status: 400 }
            );
          }

          gpsDetectedCode = closest.iata_code.toUpperCase();
          visitedCode = gpsDetectedCode;
          detectedFromGps = true;
          gpsDistanceKm = closest.distance_from_location_km;
        }

        const cleanFlightNumber =
          flight_number && String(flight_number).trim()
            ? String(flight_number).trim().toUpperCase().replace(/\s+/g, "")
            : null;

        let origCode =
          origin_iata && String(origin_iata).trim()
            ? String(origin_iata).trim().toUpperCase()
            : null;

        // 2. If a flight_number was provided, look up its origin & destination (e.g. W43304 -> LTN -> CLJ)
        //    Visited airport (`visitedCode`) stays the GPS location (e.g. LTN), while `origCode` and `flightDestCode`
        //    record the flight's origin and destination!
        let resolvedRoute = null;
        if (cleanFlightNumber && (!origCode || !flightDestCode || !visitedCode)) {
          resolvedRoute = await resolveFlightRoute(db, cleanFlightNumber);
          if (resolvedRoute) {
            if (!origCode && resolvedRoute.origin_iata) {
              origCode = resolvedRoute.origin_iata;
            }
            if (!flightDestCode && resolvedRoute.destination_iata) {
              flightDestCode = resolvedRoute.destination_iata;
            }
            if (!visitedCode) {
              visitedCode = flightDestCode || origCode || "";
            }
          }
        }

        // If user passed destination_iata explicitly alongside GPS without a flight lookup, GPS is the origin
        if (flightDestCode && !origCode && visitedCode && visitedCode !== flightDestCode) {
          origCode = visitedCode;
        }

        if (!visitedCode) {
          return jsonResponse(
            {
              error:
                "Missing required fields: provide iata_code, flight_number, or latitude and longitude for GPS check-in",
            },
            { status: 400 }
          );
        }

        // 3. If origin_iata is still blank and auto_origin is enabled, infer origin from the user's most recent airport visit
        if (!origCode && body.auto_origin === true && username) {
          try {
            const lastVisit = await db
              .prepare(
                "SELECT iata_code FROM airport_visits WHERE username = ? AND iata_code != ? ORDER BY visit_date DESC, id DESC LIMIT 1"
              )
              .bind(username, visitedCode)
              .first();
            if (lastVisit && lastVisit.iata_code) {
              origCode = String(lastVisit.iata_code).trim().toUpperCase();
            }
          } catch {
            // Non-fatal if previous visit lookup fails
          }
        }

        if (!flightDestCode) {
          flightDestCode = visitedCode;
        }

        // Prevent self-loop when no actual route exists
        if (!origin_iata && !flightDestCode && origCode === visitedCode) {
          origCode = null;
        }

        // Validate that visitedCode, origCode, and flightDestCode exist in the airports reference table
        const airportMap = await lookupAirportsMap(db, [
          visitedCode,
          origCode,
          flightDestCode,
        ]);
        const visitedAirport = airportMap.get(visitedCode);
        if (!visitedAirport) {
          return jsonResponse(
            { error: `Invalid or unknown iata_code '${visitedCode}'. It must match an airport in /api/airports.` },
            { status: 400 }
          );
        }

        const origAirport = origCode ? airportMap.get(origCode) : null;
        if (origCode && !origAirport) {
          return jsonResponse(
            { error: `Invalid or unknown origin_iata '${origCode}'. It must match an airport in /api/airports.` },
            { status: 400 }
          );
        }

        const destAirport = flightDestCode
          ? airportMap.get(flightDestCode) || visitedAirport
          : visitedAirport;

        const resolvedName =
          airport_name || (visitedAirport ? visitedAirport.name : null);

        // Calculate flight distance between origin_iata (e.g. LTN) and destination_iata (e.g. CLJ)
        const distanceKm =
          origAirport &&
          destAirport &&
          origAirport.iata_code !== destAirport.iata_code
            ? calculateDistanceKm(
                origAirport.latitude,
                origAirport.longitude,
                destAirport.latitude,
                destAirport.longitude
              )
            : null;

        try {
          await db
            .prepare("ALTER TABLE airport_visits ADD COLUMN destination_iata TEXT")
            .run();
        } catch {
          // Column already exists
        }

        let info;
        try {
          info = await db
            .prepare(
              `INSERT INTO airport_visits
                (iata_code, airport_name, visit_date, notes, username, origin_iata, destination_iata, flight_number, distance_km)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
            )
            .bind(
              visitedCode,
              resolvedName,
              resolvedVisitDate,
              notes || null,
              username,
              origCode,
              flightDestCode,
              cleanFlightNumber,
              distanceKm
            )
            .run();
        } catch {
          // Fallback if destination_iata column isn't available
          info = await db
            .prepare(
              `INSERT INTO airport_visits
                (iata_code, airport_name, visit_date, notes, username, origin_iata, flight_number, distance_km)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
            )
            .bind(
              visitedCode,
              resolvedName,
              resolvedVisitDate,
              notes || null,
              username,
              origCode,
              cleanFlightNumber,
              distanceKm
            )
            .run();
        }

        ctx.waitUntil(invalidateVisitCaches(cache, url.origin, [username]));

        const hasRoute = origCode && flightDestCode && origCode !== flightDestCode;
        const routeLabel = hasRoute
          ? `${origCode} → ${flightDestCode}`
          : visitedCode;
        const routeParts = [routeLabel];
        if (cleanFlightNumber) routeParts.push(cleanFlightNumber);
        if (distanceKm != null) routeParts.push(`${distanceKm} km`);
        const detailsBadge = routeParts.join(" · ");

        return jsonResponse({
          success: true,
          id: info.meta.last_row_id,
          username,
          iata_code: visitedCode,
          origin_iata: origCode,
          destination_iata: flightDestCode,
          flight_number: cleanFlightNumber,
          airport_name: resolvedName,
          city: visitedAirport.city || null,
          country: visitedAirport.country || null,
          visit_date: resolvedVisitDate,
          distance_km: distanceKm,
          detected_from_gps: detectedFromGps,
          gps_distance_km: gpsDistanceKm,
          changes: info.meta.changes,
          message: detectedFromGps
            ? `Checked in at ${resolvedName} (${detailsBadge}) — ${gpsDistanceKm} km away! ✈️`
            : `Checked in at ${resolvedName} (${detailsBadge})! ✈️`,
        });
      } catch (err) {
        return jsonResponse({ error: err.message }, { status: 500 });
      }
    }

    // =========================================================================
    // POST /api/visits/batch - Bulk insert visits via D1 db.batch() (Protected)
    // =========================================================================
    if (request.method === "POST" && url.pathname === "/api/visits/batch") {
      const { user, errorResponse } = await authenticateRequest(request, env, db);
      if (errorResponse) return errorResponse;

      try {
        const body = await request.json();
        const visits = Array.isArray(body) ? body : body.visits;

        if (!Array.isArray(visits) || visits.length === 0) {
          return jsonResponse(
            { error: "Request body must contain a non-empty 'visits' array" },
            { status: 400 }
          );
        }

        const allCodes = [];
        for (const v of visits) {
          if (!v.iata_code || !v.visit_date) {
            return jsonResponse(
              { error: "Every visit in batch must include iata_code and visit_date" },
              { status: 400 }
            );
          }
          allCodes.push(v.iata_code);
          if (v.origin_iata) allCodes.push(v.origin_iata);
        }

        const airportMap = await lookupAirportsMap(db, allCodes);
        const insertStmt = db.prepare(
          `INSERT INTO airport_visits
            (iata_code, airport_name, visit_date, notes, username, origin_iata, flight_number, distance_km)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
        );

        const statements = [];
        const affectedUsers = new Set();

        for (const v of visits) {
          const destCode = String(v.iata_code).trim().toUpperCase();
          const origCode = v.origin_iata ? String(v.origin_iata).trim().toUpperCase() : null;
          const destAirport = airportMap.get(destCode);
          if (!destAirport) {
            return jsonResponse(
              { error: `Invalid or unknown iata_code '${destCode}'. It must match an airport in /api/airports.` },
              { status: 400 }
            );
          }

          const origAirport = origCode ? airportMap.get(origCode) : null;
          if (origCode && !origAirport) {
            return jsonResponse(
              { error: `Invalid or unknown origin_iata '${origCode}'. It must match an airport in /api/airports.` },
              { status: 400 }
            );
          }

          const resolvedName = v.airport_name || (destAirport ? destAirport.name : null);
          const distanceKm =
            origAirport && destAirport
              ? calculateDistanceKm(
                  origAirport.latitude,
                  origAirport.longitude,
                  destAirport.latitude,
                  destAirport.longitude
                )
              : null;

          const resolvedUsername = user.username || v.username || null;
          if (resolvedUsername) affectedUsers.add(resolvedUsername);

          statements.push(
            insertStmt.bind(
              destCode,
              resolvedName,
              v.visit_date,
              v.notes || null,
              resolvedUsername,
              origCode,
              v.flight_number || null,
              distanceKm
            )
          );
        }

        const batchResults = await db.batch(statements);
        const totalInserted = batchResults.reduce((sum, r) => sum + (r.meta?.changes || 0), 0);

        ctx.waitUntil(invalidateVisitCaches(cache, url.origin, [...affectedUsers]));

        return jsonResponse({
          success: true,
          inserted: totalInserted,
          batch_size: statements.length,
        });
      } catch (err) {
        return jsonResponse({ error: err.message }, { status: 500 });
      }
    }

    // =========================================================================
    // PATCH or PUT /api/visits (or /api/visits/:id) - Edit/update a visit (Protected)
    // =========================================================================
    if (
      (request.method === "PATCH" || request.method === "PUT") &&
      (url.pathname === "/api/visits" || url.pathname.startsWith("/api/visits/"))
    ) {
      const { user, errorResponse } = await authenticateRequest(request, env, db);
      if (errorResponse) return errorResponse;

      try {
        const pathId = url.pathname.startsWith("/api/visits/")
          ? url.pathname.slice("/api/visits/".length)
          : null;
        const body = await request.json();
        const visitId = pathId || body.id;

        if (!visitId) {
          return jsonResponse({ error: "Missing required field: id" }, { status: 400 });
        }

        const existing = await db
          .prepare("SELECT * FROM airport_visits WHERE id = ?")
          .bind(visitId)
          .first();

        if (!existing) {
          return jsonResponse({ error: "No record found with the provided id" }, { status: 404 });
        }

        const nextIata = body.iata_code
          ? String(body.iata_code).trim().toUpperCase()
          : existing.iata_code;
        let nextOrigin =
          body.origin_iata !== undefined
            ? body.origin_iata
              ? String(body.origin_iata).trim().toUpperCase()
              : null
            : existing.origin_iata;
        let nextDestIata =
          body.destination_iata !== undefined
            ? body.destination_iata
              ? String(body.destination_iata).trim().toUpperCase()
              : null
            : existing.destination_iata || null;
        const nextFlightNumber =
          body.flight_number !== undefined
            ? body.flight_number
              ? String(body.flight_number).trim().toUpperCase().replace(/\s+/g, "")
              : null
            : existing.flight_number;

        // If a flight_number is set and origin or destination is missing (or equal), resolve the flight route
        if (nextFlightNumber && (!nextOrigin || !nextDestIata || nextOrigin === nextDestIata)) {
          const resolvedRoute = await resolveFlightRoute(db, nextFlightNumber);
          if (resolvedRoute) {
            if (!nextOrigin || nextOrigin === nextDestIata) {
              nextOrigin = resolvedRoute.origin_iata || nextOrigin;
            }
            if (!nextDestIata || nextOrigin === nextDestIata) {
              nextDestIata = resolvedRoute.destination_iata || nextDestIata;
            }
          }
        }

        if (!nextDestIata) {
          nextDestIata = nextIata;
        }

        const airportMap = await lookupAirportsMap(db, [
          nextIata,
          nextOrigin,
          nextDestIata,
        ]);
        const visitedAirport = airportMap.get(nextIata);
        if (!visitedAirport) {
          return jsonResponse(
            { error: `Invalid or unknown iata_code '${nextIata}'. It must match an airport in /api/airports.` },
            { status: 400 }
          );
        }

        const origAirport = nextOrigin ? airportMap.get(nextOrigin) : null;
        if (nextOrigin && !origAirport) {
          return jsonResponse(
            { error: `Invalid or unknown origin_iata '${nextOrigin}'. It must match an airport in /api/airports.` },
            { status: 400 }
          );
        }

        const destAirport = nextDestIata
          ? airportMap.get(nextDestIata) || visitedAirport
          : visitedAirport;

        let nextAirportName =
          body.airport_name !== undefined ? body.airport_name : existing.airport_name;
        if (body.iata_code && body.airport_name === undefined && visitedAirport) {
          nextAirportName = visitedAirport.name;
        }

        const nextDistanceKm =
          origAirport &&
          destAirport &&
          origAirport.iata_code !== destAirport.iata_code
            ? calculateDistanceKm(
                origAirport.latitude,
                origAirport.longitude,
                destAirport.latitude,
                destAirport.longitude
              )
            : body.origin_iata === null
            ? null
            : existing.distance_km ?? null;

        const nextVisitDate = body.visit_date ?? existing.visit_date;
        const nextNotes = body.notes !== undefined ? body.notes : existing.notes;
        const nextUsername =
          user.username || (body.username !== undefined ? body.username : existing.username);

        try {
          await db
            .prepare("ALTER TABLE airport_visits ADD COLUMN destination_iata TEXT")
            .run();
        } catch {
          // Column already exists
        }

        let info;
        try {
          info = await db
            .prepare(
              `UPDATE airport_visits
               SET iata_code = ?,
                   airport_name = ?,
                   visit_date = ?,
                   notes = ?,
                   username = ?,
                   origin_iata = ?,
                   destination_iata = ?,
                   flight_number = ?,
                   distance_km = ?
               WHERE id = ?`
            )
            .bind(
              nextIata,
              nextAirportName,
              nextVisitDate,
              nextNotes,
              nextUsername,
              nextOrigin,
              nextDestIata,
              nextFlightNumber,
              nextDistanceKm,
              visitId
            )
            .run();
        } catch {
          info = await db
            .prepare(
              `UPDATE airport_visits
               SET iata_code = ?,
                   airport_name = ?,
                   visit_date = ?,
                   notes = ?,
                   username = ?,
                   origin_iata = ?,
                   flight_number = ?,
                   distance_km = ?
               WHERE id = ?`
            )
            .bind(
              nextIata,
              nextAirportName,
              nextVisitDate,
              nextNotes,
              nextUsername,
              nextOrigin,
              nextFlightNumber,
              nextDistanceKm,
              visitId
            )
            .run();
        }

        ctx.waitUntil(
          invalidateVisitCaches(cache, url.origin, [existing.username, nextUsername])
        );

        return jsonResponse({
          success: true,
          id: Number(visitId),
          changes: info.meta.changes,
          distance_km: nextDistanceKm,
        });
      } catch (err) {
        return jsonResponse({ error: err.message }, { status: 500 });
      }
    }

    // =========================================================================
    // DELETE /api/visits (or /api/visits/:id) - Protected delete access
    // =========================================================================
    if (
      request.method === "DELETE" &&
      (url.pathname === "/api/visits" || url.pathname.startsWith("/api/visits/"))
    ) {
      const { errorResponse } = await authenticateRequest(request, env, db);
      if (errorResponse) return errorResponse;

      try {
        const pathId = url.pathname.startsWith("/api/visits/")
          ? url.pathname.slice("/api/visits/".length)
          : null;
        const body = pathId ? {} : await request.json();
        const id = pathId || body.id;

        if (!id) {
          return jsonResponse({ error: "Missing required field: id" }, { status: 400 });
        }

        const info = await db
          .prepare("DELETE FROM airport_visits WHERE id = ?")
          .bind(id)
          .run();

        if (info.meta.changes === 0) {
          return jsonResponse(
            { error: "No record found with the provided id" },
            { status: 404 }
          );
        }

        ctx.waitUntil(invalidateVisitCaches(cache, url.origin));

        return jsonResponse({ success: true, changes: info.meta.changes });
      } catch (err) {
        return jsonResponse({ error: err.message }, { status: 500 });
      }
    }

    return new Response(
      "Airport Tracker API is running. Endpoints: POST /api/login, POST /api/2fa/totp/setup, POST /api/webauthn/*, GET/POST/PATCH/DELETE /api/visits, GET /api/stats, GET/POST /api/airports",
      { status: 200, headers: CORS_HEADERS }
    );
  },
};
