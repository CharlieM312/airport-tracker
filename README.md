# Airport Tracker API

A serverless Cloudflare Worker + D1 database backend for tracking airport visits, flight routes, great-circle distances, and travel statistics.

[![Test](https://github.com/CharlieM312/airport-tracker/actions/workflows/test.yml/badge.svg)](https://github.com/CharlieM312/airport-tracker/actions/workflows/test.yml)

## Documentation

- **[API Reference (`API.md`)](./API.md)** — Full documentation of all public & protected endpoints, query parameters, database schema, and JSON payloads for frontend integration.

## Quick Start

```bash
# Start local development server
npx wrangler dev

# Apply D1 migrations locally
npx wrangler d1 migrations apply airport-db --local

# Apply D1 migrations to production
npx wrangler d1 migrations apply airport-db --remote

# Deploy Worker to Cloudflare
npx wrangler deploy
```

## Project Structure

- `src/index.js` — Cloudflare Worker request router, Haversine distance calculator, D1 Sessions API integration, and Edge Cache invalidation.
- `migrations/0001_init.sql` — Initial `airport_visits` table schema.
- `migrations/0002_add_indexes.sql` — Indexes for date sorting (`idx_visits_date`) and user-filtered queries (`idx_visits_user_date`).
- `migrations/0003_airports_and_flights.sql` — `airports` reference table with UK & international airport coordinates, foreign key constraints, and flight leg columns (`origin_iata`, `flight_number`, `distance_km`).
- `migrations/0004_users_and_sessions.sql` — `users` table with `username`, `password`, and indexed `session_token` for database-backed authentication.
- `migrations/0005_2fa_and_webauthn.sql` — Adds `totp_secret`, `totp_pending_secret`, and `webauthn_challenge` to `users` and creates `user_passkeys` for Microsoft Authenticator (TOTP) and multiple YubiKeys/Passkeys (`WebAuthn`).
- `migrations/0006_oauth_and_admin_approval.sql` — Adds `role`, `status` (`'pending' | 'approved' | 'rejected'`), and `email` to `users`, and creates `user_oauth_accounts` & `oauth_states` for GitHub, Google, Microsoft, and Apple OAuth with Admin Approval gating.
- `migrations/0007_security_hardening.sql` — Adds brute-force lockout columns (`failed_login_attempts`, `locked_until`) to `users`, multi-device sessions (`user_sessions`), and SHA-256 hashed Personal Access Tokens (`user_api_keys`).
- `wrangler.jsonc` — Cloudflare Worker & D1 binding configuration.

