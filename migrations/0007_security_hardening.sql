-- 1. Brute-force / rate-limit tracking columns on users
ALTER TABLE users ADD COLUMN failed_login_attempts INTEGER NOT NULL DEFAULT 0;
ALTER TABLE users ADD COLUMN locked_until INTEGER;

-- 2. Multi-device user sessions with expiration & device metadata
CREATE TABLE IF NOT EXISTS user_sessions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT NOT NULL REFERENCES users(username) ON DELETE CASCADE ON UPDATE CASCADE,
  token TEXT NOT NULL UNIQUE,
  user_agent TEXT,
  ip_address TEXT,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  last_used_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  expires_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_user_sessions_username ON user_sessions (username);
CREATE INDEX IF NOT EXISTS idx_user_sessions_token ON user_sessions (token);

-- 3. Personal Access Tokens / API Keys (stored as SHA-256 hashes)
CREATE TABLE IF NOT EXISTS user_api_keys (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT NOT NULL REFERENCES users(username) ON DELETE CASCADE ON UPDATE CASCADE,
  label TEXT NOT NULL,
  key_prefix TEXT NOT NULL,
  key_hash TEXT NOT NULL UNIQUE,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  last_used_at DATETIME,
  expires_at INTEGER
);

CREATE INDEX IF NOT EXISTS idx_user_api_keys_username ON user_api_keys (username);
CREATE INDEX IF NOT EXISTS idx_user_api_keys_hash ON user_api_keys (key_hash);
