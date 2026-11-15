/**
 * Airport Tracker Worker API
 *
 * Authentication & 2FA / WebAuthn Endpoints:
 * - POST   /api/login                     (Validates username, password, and optional 6-digit TOTP code)
 * - POST   /api/logout                    (Clears the active session_token in `users`)
 * - GET    /api/2fa/status                (Protected: returns { totp_enabled, webauthn_enabled })
 * - POST   /api/2fa/totp/setup            (Protected: generates pending Base32 TOTP secret & otpauth:// URI)
 * - POST   /api/2fa/totp/verify           (Protected: verifies a 6-digit code and activates totp_secret)
 * - DELETE /api/2fa/totp                  (Protected: disables Authenticator TOTP 2FA)
 * - DELETE /api/webauthn                  (Protected: removes registered YubiKey / security key)
 * - DELETE /api/2fa                       (Protected: disables TOTP, WebAuthn, or both)
 * - POST   /api/webauthn/register-options (Protected: generates challenge to enroll a YubiKey / Passkey)
 * - POST   /api/webauthn/register-verify  (Protected: saves YubiKey credential_id & SPKI public_key)
 * - POST   /api/webauthn/login-options    (Public: generates challenge & allowCredentials for YubiKey sign-in)
 * - POST   /api/webauthn/login-verify     (Public: verifies YubiKey ECDSA P-256 signature & issues session token)
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

  // 1. Check session_token in D1 `users` table
  try {
    const user = await db
      .prepare("SELECT id, username FROM users WHERE session_token = ?")
      .bind(token)
      .first();

    if (user) {
      return { user, errorResponse: null };
    }
  } catch {
    // If users table does not exist yet, fall through to API_SECRET check
  }

  // 2. Fallback: allow static env.API_SECRET for CLI / administrative tasks if configured
  if (env.API_SECRET && token === env.API_SECRET) {
    return { user: { username: null, isApiSecret: true }, errorResponse: null };
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
    // POST /api/login - Validate credentials (+ optional TOTP) & issue session token
    // =========================================================================
    if (request.method === "POST" && url.pathname === "/api/login") {
      try {
        const body = await request.json();
        const { username, password, totp_code } = body;

        if (!username || !password) {
          return jsonResponse(
            { error: "Username and password are required" },
            { status: 400 }
          );
        }

        const user = await db
          .prepare("SELECT * FROM users WHERE username = ? AND password = ?")
          .bind(username, password)
          .first();

        if (!user) {
          return jsonResponse(
            { error: "Invalid username or password" },
            { status: 401 }
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
            return jsonResponse(
              { error: "Invalid 6-digit Authenticator code" },
              { status: 401 }
            );
          }
        }

        const sessionToken = crypto.randomUUID();
        await db
          .prepare("UPDATE users SET session_token = ? WHERE username = ?")
          .bind(sessionToken, user.username)
          .run();

        return jsonResponse({
          success: true,
          token: sessionToken,
          username: user.username,
        });
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
    // GET /api/2fa/status - Check enabled 2FA methods for current user (Protected)
    // =========================================================================
    if (request.method === "GET" && url.pathname === "/api/2fa/status") {
      const { user, errorResponse } = await authenticateRequest(request, env, db);
      if (errorResponse) return errorResponse;
      if (!user.username) {
        return jsonResponse({ totp_enabled: false, webauthn_enabled: false });
      }

      try {
        const record = await db
          .prepare(
            "SELECT totp_secret, webauthn_credential_id FROM users WHERE username = ?"
          )
          .bind(user.username)
          .first();

        return jsonResponse({
          username: user.username,
          totp_enabled: Boolean(record && record.totp_secret),
          webauthn_enabled: Boolean(record && record.webauthn_credential_id),
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
        if (url.pathname === "/api/2fa/totp" || url.pathname === "/api/2fa/totp/disable") {
          targetType = "totp";
        } else if (url.pathname === "/api/2fa/webauthn" || url.pathname === "/api/webauthn") {
          targetType = "webauthn";
        } else {
          try {
            const body = await request.json();
            if (body && body.type) targetType = body.type;
          } catch {
            // Default to disabling all 2FA if no JSON body was provided on DELETE /api/2fa
          }
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
          await db
            .prepare(
              "UPDATE users SET webauthn_credential_id = NULL, webauthn_public_key = NULL, webauthn_challenge = NULL WHERE username = ?"
            )
            .bind(user.username)
            .run();
        } else {
          try {
            await db
              .prepare(
                "UPDATE users SET totp_secret = NULL, totp_pending_secret = NULL, webauthn_credential_id = NULL, webauthn_public_key = NULL, webauthn_challenge = NULL WHERE username = ?"
              )
              .bind(user.username)
              .run();
          } catch {
            await db
              .prepare(
                "UPDATE users SET totp_secret = NULL, webauthn_credential_id = NULL, webauthn_public_key = NULL, webauthn_challenge = NULL WHERE username = ?"
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

        return jsonResponse({
          challenge,
          rpId: getRpId(request, url),
          pubKeyCredParams: [
            { alg: -7, type: "public-key" },
            { alg: -257, type: "public-key" },
          ],
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
        const { credential_id, public_key } = await request.json();
        if (!credential_id || !public_key) {
          return jsonResponse(
            { error: "Missing required fields: credential_id and public_key" },
            { status: 400 }
          );
        }

        await db
          .prepare(
            "UPDATE users SET webauthn_credential_id = ?, webauthn_public_key = ?, webauthn_challenge = NULL WHERE username = ?"
          )
          .bind(credential_id, public_key, user.username)
          .run();

        return jsonResponse({ success: true });
      } catch (err) {
        return jsonResponse({ error: err.message }, { status: 500 });
      }
    }

    // =========================================================================
    // POST /api/webauthn/login-options - Issue challenge for YubiKey sign-in
    // =========================================================================
    if (request.method === "POST" && url.pathname === "/api/webauthn/login-options") {
      try {
        const { username, password } = await request.json();
        if (!username) {
          return jsonResponse({ error: "Username is required" }, { status: 400 });
        }

        const user = await db
          .prepare(
            "SELECT username, password, webauthn_credential_id FROM users WHERE username = ?"
          )
          .bind(username)
          .first();

        if (!user || !user.webauthn_credential_id) {
          return jsonResponse(
            { error: "No YubiKey or security key registered for this user" },
            { status: 400 }
          );
        }

        // If password was also supplied by the user, verify it matches
        if (password !== undefined && password !== "" && user.password !== password) {
          return jsonResponse({ error: "Invalid username or password" }, { status: 401 });
        }

        const challenge = bytesToBase64Url(crypto.getRandomValues(new Uint8Array(32)));
        await db
          .prepare("UPDATE users SET webauthn_challenge = ? WHERE username = ?")
          .bind(challenge, user.username)
          .run();

        return jsonResponse({
          challenge,
          rpId: getRpId(request, url),
          allowCredentials: [{ id: user.webauthn_credential_id, type: "public-key" }],
        });
      } catch (err) {
        return jsonResponse({ error: err.message }, { status: 500 });
      }
    }

    // =========================================================================
    // POST /api/webauthn/login-verify - Verify YubiKey ECDSA signature & issue session token
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
          .prepare(
            "SELECT * FROM users WHERE username = ? AND webauthn_credential_id = ?"
          )
          .bind(username, credential_id)
          .first();

        if (!user || !user.webauthn_public_key || !user.webauthn_challenge) {
          return jsonResponse(
            { error: "Invalid security key login state" },
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

        const spkiBytes = base64UrlToBytes(user.webauthn_public_key);
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
          return jsonResponse(
            { error: "Security key signature verification failed" },
            { status: 401 }
          );
        }

        const sessionToken = crypto.randomUUID();
        await db
          .prepare(
            "UPDATE users SET session_token = ?, webauthn_challenge = NULL WHERE username = ?"
          )
          .bind(sessionToken, user.username)
          .run();

        return jsonResponse({
          success: true,
          token: sessionToken,
          username: user.username,
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
          const query = `
            SELECT
              v.id,
              v.iata_code,
              COALESCE(v.airport_name, a.name) AS airport_name,
              v.visit_date,
              v.username,
              v.notes,
              v.origin_iata,
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
    // GET /api/airports - Reference table lookup (?code=LHR or ?search=London)
    // =========================================================================
    if (request.method === "GET" && url.pathname === "/api/airports") {
      try {
        const cached = await cache.match(request);
        if (cached) return cached;

        const code = url.searchParams.get("code");
        const search = url.searchParams.get("search");

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

        // Automatically use the authenticated user's username (fallback to body.username for API_SECRET)
        const username = user.username || body.username || null;

        if (!iata_code || !visit_date) {
          return jsonResponse(
            { error: "Missing required fields: iata_code and visit_date" },
            { status: 400 }
          );
        }

        const destCode = String(iata_code).trim().toUpperCase();
        const origCode = origin_iata ? String(origin_iata).trim().toUpperCase() : null;

        // Validate that iata_code (and origin_iata if given) exist in the airports reference table
        const airportMap = await lookupAirportsMap(db, [destCode, origCode]);
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

        const resolvedName = airport_name || (destAirport ? destAirport.name : null);
        const distanceKm =
          origAirport && destAirport
            ? calculateDistanceKm(
                origAirport.latitude,
                origAirport.longitude,
                destAirport.latitude,
                destAirport.longitude
              )
            : null;

        let info;
        try {
          info = await db
            .prepare(
              `INSERT INTO airport_visits
                (iata_code, airport_name, visit_date, notes, username, origin_iata, flight_number, distance_km)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
            )
            .bind(
              destCode,
              resolvedName,
              visit_date,
              notes || null,
              username,
              origCode,
              flight_number || null,
              distanceKm
            )
            .run();
        } catch {
          // Fallback if 0003 migration columns aren't applied yet
          info = await db
            .prepare(
              "INSERT INTO airport_visits (iata_code, airport_name, visit_date, notes, username) VALUES (?, ?, ?, ?, ?)"
            )
            .bind(destCode, resolvedName, visit_date, notes || null, username)
            .run();
        }

        ctx.waitUntil(invalidateVisitCaches(cache, url.origin, [username]));

        return jsonResponse({
          success: true,
          id: info.meta.last_row_id,
          username,
          airport_name: resolvedName,
          distance_km: distanceKm,
          changes: info.meta.changes,
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
        const nextOrigin =
          body.origin_iata !== undefined
            ? body.origin_iata
              ? String(body.origin_iata).trim().toUpperCase()
              : null
            : existing.origin_iata;

        const airportMap = await lookupAirportsMap(db, [nextIata, nextOrigin]);
        const destAirport = airportMap.get(nextIata);
        if (!destAirport) {
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

        let nextAirportName =
          body.airport_name !== undefined ? body.airport_name : existing.airport_name;
        if (body.iata_code && body.airport_name === undefined && destAirport) {
          nextAirportName = destAirport.name;
        }

        const nextDistanceKm =
          origAirport && destAirport
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
        const nextFlightNumber =
          body.flight_number !== undefined ? body.flight_number : existing.flight_number;

        const info = await db
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
