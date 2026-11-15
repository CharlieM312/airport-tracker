CREATE TABLE IF NOT EXISTS airport_visits (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  iata_code TEXT NOT NULL,
  airport_name TEXT,
  visit_date TEXT NOT NULL,
  username TEXT NOT NULL,
  notes TEXT,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);