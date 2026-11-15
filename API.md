# Airport Tracker API Documentation

Cloudflare Worker + D1 API for tracking airport visits, flight legs, airport reference coordinates, and travel statistics.

## Base URL & Authentication

- **Public Read Endpoints** (`GET`): Open access, cached at the Cloudflare edge (`Cache-Control: public, max-age=60, s-maxage=300, stale-while-revalidate=600`), and routed via the D1 Sessions API (`x-d1-bookmark` header) for Global Read Replication.
- **Protected Write Endpoints** (`POST`, `PATCH`, `PUT`, `DELETE`): Require a Bearer token in the `Authorization` header:
  ```http
  Authorization: Bearer <API_SECRET>
  ```
- **Automatic Cache Invalidation**: Any write (`POST`, `PATCH`, `PUT`, `DELETE`) automatically invalidates cached `GET` responses.

---

## Database Schema Overview

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
| `username` | `TEXT NOT NULL` | User identifier (e.g., `CharlieM312`) |
| `notes` | `TEXT` | Optional visit/flight notes |
| `origin_iata` | `TEXT` | Optional origin airport code referencing `airports(iata_code)` |
| `flight_number` | `TEXT` | Optional flight number (e.g., `BA968`) |
| `distance_km` | `REAL` | Great-circle distance in km (auto-calculated via Haversine when `origin_iata` is provided) |
| `created_at` | `DATETIME` | Timestamp when the record was created |

---

## Public Read Endpoints

### 1. `GET /api/visits`
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

### 2. `GET /api/visits/airports`
Returns visited airport IATA codes (uses covering index `idx_visits_user_date`).

**Query Parameters:**
- `username` *(optional)*: Filter by username.
- `distinct` *(optional)*: Set `?distinct=true` to group by `iata_code` and include `visit_count` and `last_visit_date`.

**Example Response (`?distinct=true`):**
```json
[
  {
    "iata_code": "HAM",
    "last_visit_date": "2026-09-15",
    "visit_count": 1
  }
]
```

---

### 3. `GET /api/stats`
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

### 4. `GET /api/airports`
Look up or search airports in the `airports` reference table.

**Query Parameters:**
- `code` *(optional)*: Exact 3-letter IATA code lookup (e.g., `?code=LHR`).
- `search` *(optional)*: Case-insensitive substring search across `iata_code`, `name`, `city`, and `country` (e.g., `?search=London`).

---

## Protected Write Endpoints

### 5. `POST /api/visits`
Log a new airport visit. Validates that `iata_code` (and `origin_iata`, if provided) exists in `airports`, auto-populates `airport_name` if omitted, and auto-computes Haversine `distance_km`.

**Request Body:**
```json
{
  "iata_code": "HAM",
  "origin_iata": "LHR",
  "visit_date": "2026-09-15",
  "username": "CharlieM312",
  "flight_number": "BA968",
  "notes": "First flight logged"
}
```

**Response (`200 OK`):**
```json
{
  "success": true,
  "id": 1,
  "airport_name": "Hamburg Airport",
  "distance_km": 745.0,
  "changes": 1
}
```

---

### 6. `POST /api/visits/batch`
Bulk-insert multiple visits in a single D1 `db.batch()` call. Automatically validates IATA codes against `airports`, resolves `airport_name`, and calculates `distance_km`.

**Request Body:**
```json
{
  "visits": [
    {
      "iata_code": "NCL",
      "origin_iata": "LHR",
      "visit_date": "2026-10-01",
      "username": "CharlieM312",
      "flight_number": "BA1326"
    },
    {
      "iata_code": "BRS",
      "visit_date": "2026-10-12",
      "username": "CharlieM312"
    }
  ]
}
```

---

### 7. `PATCH /api/visits/:id` *(or `PATCH /api/visits`)*
Edit an existing visit by ID (passed in the URL path `/api/visits/1` or in the JSON body `{"id": 1, ...}`). Only fields included in the body are updated, and `distance_km` is automatically recalculated if `iata_code` or `origin_iata` changes.

**Request Body:**
```json
{
  "origin_iata": "LHR",
  "iata_code": "HAM",
  "flight_number": "BA968",
  "notes": "Updated flight details"
}
```

---

### 8. `DELETE /api/visits/:id` *(or `DELETE /api/visits`)*
Delete a visit by ID (passed in the URL path `/api/visits/1` or in the JSON body `{"id": 1}`).

---

### 9. `POST /api/airports`
Add or upsert a single airport object or an array of airports (`{ "airports": [...] }`) into the `airports` reference table using `db.batch()`.

**Request Body:**
```json
{
  "iata_code": "HAM",
  "name": "Hamburg Airport",
  "city": "Hamburg",
  "country": "Germany",
  "latitude": 53.6304,
  "longitude": 9.9882
}
```
