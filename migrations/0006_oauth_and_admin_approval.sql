-- 1. Add role, approval status, and email columns to users
-- Existing users default to 'approved'; new OAuth/registration requests are inserted as 'pending'
ALTER TABLE users ADD COLUMN role TEXT NOT NULL DEFAULT 'user';
ALTER TABLE users ADD COLUMN status TEXT NOT NULL DEFAULT 'approved';
ALTER TABLE users ADD COLUMN email TEXT;

-- Promote the primary owner account to admin
UPDATE users SET role = 'admin', status = 'approved' WHERE username = 'CharlieM312' OR id = 1;

-- Ensure users.username has a unique index for foreign key references
CREATE UNIQUE INDEX IF NOT EXISTS idx_users_username ON users (username);

-- 2. Store linked OAuth identities (GitHub, Google, Microsoft, Apple) per user
CREATE TABLE IF NOT EXISTS user_oauth_accounts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT NOT NULL REFERENCES users(username) ON DELETE CASCADE ON UPDATE CASCADE,
  provider TEXT NOT NULL,
  provider_user_id TEXT NOT NULL,
  email TEXT,
  display_name TEXT,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(provider, provider_user_id)
);

CREATE INDEX IF NOT EXISTS idx_user_oauth_username ON user_oauth_accounts (username);

-- 3. Short-lived CSRF state nonces for OAuth sign-in / linking flows
CREATE TABLE IF NOT EXISTS oauth_states (
  state TEXT PRIMARY KEY,
  provider TEXT NOT NULL,
  redirect_uri TEXT,
  link_username TEXT,
  created_at INTEGER NOT NULL
);
