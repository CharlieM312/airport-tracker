# Airport Tracker API Documentation

Cloudflare Worker + D1 API for tracking airport visits, flight legs, airport reference coordinates, travel statistics, and session-token authentication.

## Authentication & Session Tokens

- **Login (`POST /api/login`)**: Validates `username` and `password` against the `users` table in D1, generates a unique `session_token` (`crypto.randomUUID()`), stores it on the user record, and returns `{ success: true, token, username }`.
- **Protected Write Endpoints** (`POST`, `PATCH`, `PUT`, `DELETE`): Require the session token in the `Authorization` header:
  ```http
  Authorization: Bearer <session_token>
  ```
  When authenticated with a session token, write endpoints automatically associate visits with the logged-in user's `username`.
- **Public Read Endpoints** (`GET`): Open access, cached at the Cloudflare edge (`Cache-Control: public, max-age=60, s-maxage=300, stale-while-revalidate=600`), and routed via the D1 Sessions API (`x-d1-bookmark` header) for Global Read Replication.
- **CORS**: All endpoints return `Access-Control-Allow-Origin: *` and handle `OPTIONS` preflight requests.

---

## Database Schema Overview

### `users`
| Column | Type | Description |
| :--- | :--- | :--- |
| `id` | `INTEGER PRIMARY KEY` | Auto-incrementing user ID |
| `username` | `TEXT NOT NULL UNIQUE` | Unique username (e.g., `CharlieM312`) |
| `password` | `TEXT NOT NULL` | User password (`''` for OAuth-only accounts) |
| `email` | `TEXT` | Optional user email address |
| `role` | `TEXT NOT NULL DEFAULT 'user'` | `'admin'` or `'user'` (`CharlieM312` / `id = 1` is `'admin'`) |
| `status` | `TEXT NOT NULL DEFAULT 'approved'` | `'pending'`, `'approved'`, or `'rejected'` (new OAuth / registered accounts start as `'pending'`) |
| `session_token` | `TEXT` | Active session token issued by `POST /api/login`, `POST /api/oauth/login`, or `POST /api/webauthn/login-verify` |
| `totp_secret` | `TEXT` | Active Base32 RFC 6238 TOTP secret for Microsoft / Yubico Authenticator |
| `totp_pending_secret` | `TEXT` | Unverified Base32 TOTP secret awaiting 6-digit code confirmation |
| `webauthn_challenge` | `TEXT` | Ephemeral WebAuthn challenge for registration or sign-in |
| `created_at` | `DATETIME` | Timestamp when the user was created |

### `user_oauth_accounts`
| Column | Type | Description |
| :--- | :--- | :--- |
| `id` | `INTEGER PRIMARY KEY` | Auto-incrementing OAuth link ID |
| `username` | `TEXT NOT NULL` | Foreign key referencing `users(username) ON DELETE CASCADE ON UPDATE CASCADE` |
| `provider` | `TEXT NOT NULL` | `'github'`, `'google'`, `'microsoft'`, or `'apple'` |
| `provider_user_id` | `TEXT NOT NULL` | Unique subject/user ID (`sub`) from the OAuth provider |
| `email` | `TEXT` | Verified email address from the OAuth provider |
| `display_name` | `TEXT` | Display name or handle from the OAuth provider |
| `created_at` | `DATETIME` | Timestamp when the OAuth identity was linked |

### `user_passkeys`
| Column | Type | Description |
| :--- | :--- | :--- |
| `id` | `INTEGER PRIMARY KEY` | Auto-incrementing passkey ID |
| `username` | `TEXT NOT NULL` | Foreign key referencing `users(username)` |
| `credential_id` | `TEXT NOT NULL UNIQUE` | Base64URL-encoded WebAuthn credential ID |
| `public_key` | `TEXT NOT NULL` | Base64URL-encoded SPKI (`ES256` or `RS256`) public key |
| `label` | `TEXT` | User-friendly name (e.g., `YubiKey 5 NFC`, `Security Key #1`) |
| `created_at` | `DATETIME` | Timestamp when the passkey was registered |

### `airports` (Reference Table)
| Column | Type | Description |
| :--- | :--- | :--- |
| `iata_code` | `TEXT PRIMARY KEY` | 3-letter uppercase IATA code (e.g., `LHR`, `HAM`, `JFK`) |
| `name` | `TEXT NOT NULL` | Full airport name |
| `city` | `TEXT` | City / region served |
| `country` | `TEXT` | Country name |
| `latitude` | `REAL NOT NULL` | Decimal latitude |
| `longitude` | `REAL NOT NULL` | Decimal longitude |

### `airport_visits`
| Column | Type | Description |
| :--- | :--- | :--- |
| `id` | `INTEGER PRIMARY KEY` | Auto-incrementing visit ID |
| `iata_code` | `TEXT NOT NULL` | Foreign key referencing `airports(iata_code)` |
| `airport_name` | `TEXT` | Airport name (auto-populated from `airports` if omitted) |
| `visit_date` | `TEXT NOT NULL` | ISO date string (`YYYY-MM-DD`) |
| `username` | `TEXT NOT NULL` | User identifier (automatically set from the authenticated user) |
| `notes` | `TEXT` | Optional visit/flight notes |
| `origin_iata` | `TEXT` | Optional origin airport code referencing `airports(iata_code)` |
| `flight_number` | `TEXT` | Optional flight number (e.g., `BA968`) |
| `distance_km` | `REAL` | Great-circle distance in km (auto-calculated via Haversine when `origin_iata` is provided) |
| `created_at` | `DATETIME` | Timestamp when the record was created |

---

## Authentication Endpoints

### 1. `POST /api/login`
Validates credentials (and `totp_code` if `totp_secret` is enabled on the user) and generates a new `session_token`.

**Request Body:**
```json
{
  "username": "CharlieM312",
  "password": "your-password",
  "totp_code": "123456"
}
```

**Response (`200 OK`):**
```json
{
  "success": true,
  "token": "550e8400-e29b-41d4-a716-446655440000",
  "username": "CharlieM312"
}
```

### 2. `POST /api/logout`
Clears the active `session_token` in D1 for the Bearer token sent in the `Authorization` header.

### 3. `GET /api/2fa/status` *(Protected)*
Returns which 2FA methods and passkeys are currently active for the signed-in user:
```json
{
  "username": "CharlieM312",
  "totp_enabled": true,
  "webauthn_enabled": true,
  "passkey_count": 2,
  "passkeys": [
    {
      "id": 1,
      "credential_id": "base64url-id-1",
      "label": "Security Key #1",
      "created_at": "2026-11-15 22:30:00"
    }
  ]
}
```

### 4. `POST /api/2fa/totp/setup` & `POST /api/2fa/totp/verify` *(Protected)*
Two-step enrollment for Microsoft Authenticator / Yubico Authenticator so the user cannot be locked out before confirming their app generates valid codes:
1. **`POST /api/2fa/totp/setup`**: Generates a Base32 secret, stores it in `users.totp_pending_secret`, and returns `{ secret, otpauth_url, pending_verification: true }`.
2. **`POST /api/2fa/totp/verify`**: Accepts `{ "code": "123456" }` (or `{ "totp_code": "123456" }`), verifies it against `totp_pending_secret`, and promotes it to `users.totp_secret` (`{ "success": true, "totp_enabled": true }`).

### 5. `DELETE /api/2fa/totp`, `DELETE /api/webauthn`, & `DELETE /api/2fa` *(Protected)*
Remove/disable 2FA methods for the signed-in user:
- `DELETE /api/2fa/totp` (or `POST /api/2fa/totp/disable`): Clears `totp_secret` and `totp_pending_secret`.
- `DELETE /api/webauthn?credential_id=<id>` (or JSON body `{ "credential_id": "<id>" }`): Deletes a specific passkey from `user_passkeys`. Calling `DELETE /api/webauthn` without `credential_id` removes all registered passkeys for the user.
- `DELETE /api/2fa`: Disables both TOTP and WebAuthn (or pass `{ "type": "totp" | "webauthn" | "all" }`).

### 6. `POST /api/webauthn/register-options` & `POST /api/webauthn/register-verify` *(Protected)*
Enrolls a YubiKey / FIDO2 security key or passkey for the signed-in user (multiple passkeys per user supported):
- `POST /api/webauthn/register-options` returns `{ challenge, rpId, pubKeyCredParams, excludeCredentials }`.
- `POST /api/webauthn/register-verify` accepts `{ credential_id, public_key, label? }` (SPKI Base64URL) and adds it to `user_passkeys`, returning `{ success: true, passkey_count }`.

### 5. `POST /api/webauthn/login-options` & `POST /api/webauthn/login-verify` *(Public)*
Authenticates a user with their enrolled YubiKey / security key:
- `POST /api/webauthn/login-options` accepts `{ username, password? }` and returns `{ challenge, rpId, allowCredentials }`.
- `POST /api/webauthn/login-verify` verifies the ECDSA P-256 signature over `authenticatorData || SHA-256(clientDataJSON)` using Web Crypto and returns `{ success: true, token, username }`.

### 8. `GET /api/oauth/providers`, `POST /api/oauth/options`, & `POST /api/oauth/login` *(Public)*
Supports signing in with **GitHub, Google, Microsoft (Entra / Personal), and Apple** with automatic **Admin Approval** gating for new accounts:
1. **`GET /api/oauth/providers` (or `POST /api/oauth/options`)**: Issues a one-time CSRF `state` token in `oauth_states` and returns configured provider Client IDs (`GITHUB_CLIENT_ID`, `GOOGLE_CLIENT_ID`, `MICROSOFT_CLIENT_ID`, `APPLE_CLIENT_ID`).
2. **`POST /api/oauth/login`**:
   - Accepts `{ provider: "github" | "google" | "microsoft" | "apple", state?, code?, redirect_uri?, id_token?, provider_user_id?, email?, display_name?, username?, totp_code? }`.
   - Exchanges authorization `code` values automatically for **GitHub** (`GITHUB_CLIENT_ID` / `GITHUB_CLIENT_SECRET`), **Google** (`GOOGLE_CLIENT_ID` / `GOOGLE_CLIENT_SECRET` via `https://oauth2.googleapis.com/token`), and **Microsoft** (`MICROSOFT_CLIENT_ID` / `MICROSOFT_CLIENT_SECRET` via `https://login.microsoftonline.com/common/oauth2/v2.0/token`).
   - **If already linked to an `'approved'` user**: Issues a `session_token` and returns `{ success: true, token, username, provider, role, is_admin, status: "approved" }`.
   - **If new user (or `'pending'` user)**: Creates the user with `status = 'pending'` in `users` and links their OAuth identity in `user_oauth_accounts`, returning `202 Accepted` (or `403` on subsequent attempts while still pending):
     ```json
     {
       "success": false,
       "pending_approval": true,
       "status": "pending",
       "username": "new_user",
       "provider": "github",
       "message": "Your OAuth account has been registered and is awaiting admin approval before you can sign in."
     }
     ```

### 9. `POST /api/oauth/link` & `DELETE /api/oauth/link` *(Protected)*
Links or unlinks a GitHub, Google, Microsoft, or Apple account to the currently signed-in user:
- `POST /api/oauth/link`: Accepts `{ provider, code?, redirect_uri?, state?, provider_user_id?, id_token?, email?, display_name? }` and returns `{ success: true, oauth_accounts }`.
- `DELETE /api/oauth/link?provider=github` (or `?id=1`): Removes the linked OAuth account from the signed-in user.

### 10. `POST /api/register` *(Public)*
Submits a username/password account request (`{ username, password, email? }`) which creates a row in `users` with `status = 'pending'` awaiting admin approval.

### 11. `PATCH /api/user/username` (or `PATCH /api/user`) *(Protected)*
Renames the currently signed-in user's username across `users`, `airport_visits`, `user_passkeys`, and `user_oauth_accounts` in a single atomic D1 `db.batch()` transaction and purges the edge cache for both old and new usernames:
```json
{
  "new_username": "CharlieM"
}
```
**Response (`200 OK`):**
```json
{
  "success": true,
  "old_username": "CharlieM312",
  "username": "CharlieM"
}
```

### 12. `GET /api/admin/users`, `PATCH /api/admin/users/:username`, & `DELETE /api/admin/users/:username` *(Admin Only)*
Admin endpoints for approving, rejecting, renaming, or deleting user accounts:
- **`GET /api/admin/users`** (optional `?status=pending`): Returns `{ pending_count, total_count, users: [...] }` with each user's `status` (`'pending' | 'approved' | 'rejected'`), `role` (`'admin' | 'user'`), and linked `oauth_accounts`.
- **`PATCH /api/admin/users/:username`** (or `PATCH /api/admin/users` with `{ username, status?: "approved" | "rejected" | "pending", role?: "admin" | "user", new_username?: "..." }`): Approves or rejects a user account, updates their role, and/or renames their username across all tables.
- **`DELETE /api/admin/users/:username`**: Permanently deletes a pending/rejected user and cascades deletion to their `user_oauth_accounts` and `user_passkeys`.

---

## Public Read Endpoints

### 3. `GET /api/visits`
Returns visits ordered by `visit_date DESC`, joined with the `airports` reference table for coordinates and location details.

**Query Parameters:**
- `username` *(optional)*: Filter visits by username (uses composite index `idx_visits_user_date`).
- `limit` *(optional)*: Max records to return (default `100`, max `500`).
- `before` *(optional)*: Cursor pagination; returns visits with `visit_date < before` (`YYYY-MM-DD`).

**Example Response (`200 OK`):**
```json
[
  {
    "id": 1,
    "iata_code": "HAM",
    "airport_name": "Hamburg Airport",
    "visit_date": "2026-09-15",
    "username": "CharlieM312",
    "notes": "First flight logged",
    "origin_iata": "LHR",
    "flight_number": "BA968",
    "distance_km": 745.0,
    "city": "Hamburg",
    "country": "Germany",
    "latitude": 53.6304,
    "longitude": 9.9882
  }
]
```

---

### 4. `GET /api/visits/airports`
Returns visited airport IATA codes (uses covering index `idx_visits_user_date`).

**Query Parameters:**
- `username` *(optional)*: Filter by username.
- `distinct` *(optional)*: Set `?distinct=true` to group by `iata_code` and include `visit_count` and `last_visit_date`.

---

### 5. `GET /api/stats`
Executes 5 analytical queries in a single D1 `db.batch()` round-trip to return travel statistics and total distance flown.

**Query Parameters:**
- `username` *(optional)*: Filter stats for a specific user (defaults to all users).

**Example Response (`200 OK`):**
```json
{
  "username": "CharlieM312",
  "total_visits": 1,
  "unique_airports": 1,
  "unique_countries": 1,
  "first_visit_date": "2026-09-15",
  "last_visit_date": "2026-09-15",
  "total_distance_km": 745.0,
  "total_distance_miles": 462.9,
  "most_visited_airports": [
    {
      "iata_code": "HAM",
      "airport_name": "Hamburg Airport",
      "city": "Hamburg",
      "country": "Germany",
      "visit_count": 1
    }
  ],
  "countries_visited": [
    {
      "country": "Germany",
      "visit_count": 1,
      "unique_airports": 1
    }
  ],
  "visits_by_year": [
    {
      "year": "2026",
      "visit_count": 1,
      "unique_airports": 1
    }
  ]
}
```

---

### 6. `GET /api/airports`
Look up or search airports in the `airports` reference table.

**Query Parameters:**
- `code` *(optional)*: Exact 3-letter IATA code lookup (e.g., `?code=LHR`).
- `search` *(optional)*: Case-insensitive substring search across `iata_code`, `name`, `city`, and `country` (e.g., `?search=London`).

---

## Protected Write Endpoints

### 7. `POST /api/visits`
Log a new airport visit. Validates the session token in `Authorization: Bearer <token>`, sets `username` from the authenticated user, validates `iata_code` (and `origin_iata`, if provided) against `airports`, auto-populates `airport_name` if omitted, and auto-computes Haversine `distance_km`.

**Request Body:**
```json
{
  "iata_code": "HAM",
  "origin_iata": "LHR",
  "visit_date": "2026-09-15",
  "flight_number": "BA968",
  "notes": "First flight logged"
}
```

**Response (`200 OK`):**
```json
{
  "success": true,
  "id": 1,
  "username": "CharlieM312",
  "airport_name": "Hamburg Airport",
  "distance_km": 745.0,
  "changes": 1
}
```

---

### 8. `POST /api/visits/batch`
Bulk-insert multiple visits in a single D1 `db.batch()` call. Automatically associates visits with the authenticated user, validates IATA codes against `airports`, resolves `airport_name`, and calculates `distance_km`.

---

### 9. `PATCH /api/visits/:id` *(or `PATCH /api/visits`)*
Edit an existing visit by ID (passed in the URL path `/api/visits/1` or in the JSON body `{"id": 1, ...}`). Only fields included in the body are updated, and `distance_km` is automatically recalculated if `iata_code` or `origin_iata` changes.

---

### 10. `DELETE /api/visits/:id` *(or `DELETE /api/visits`)*
Delete a visit by ID (passed in the URL path `/api/visits/1` or in the JSON body `{"id": 1}`).

---

### 11. `POST /api/airports`
Add or upsert a single airport object or an array of airports (`{ "airports": [...] }`) into the `airports` reference table using `db.batch()`.
