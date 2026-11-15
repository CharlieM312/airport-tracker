-- Create users table with password and session_token support
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT NOT NULL UNIQUE,
  password TEXT NOT NULL,
  session_token TEXT,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Index session_token for fast Bearer token lookups on protected endpoints
CREATE INDEX IF NOT EXISTS idx_users_session_token ON users (session_token);
