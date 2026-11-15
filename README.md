# Airport Tracker API

A serverless Cloudflare Worker + D1 database backend for tracking airport visits, flight routes, great-circle distances, and travel statistics.

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
- `wrangler.jsonc` — Cloudflare Worker & D1 binding configuration.
