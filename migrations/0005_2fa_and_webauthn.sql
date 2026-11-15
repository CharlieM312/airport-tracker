-- Add TOTP (Microsoft/Yubico Authenticator) and WebAuthn challenge columns to users
ALTER TABLE users ADD COLUMN totp_secret TEXT;
ALTER TABLE users ADD COLUMN totp_pending_secret TEXT;
ALTER TABLE users ADD COLUMN webauthn_challenge TEXT;

-- Table to store multiple YubiKeys / Passkeys per user
CREATE TABLE IF NOT EXISTS user_passkeys (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT NOT NULL REFERENCES users(username) ON DELETE CASCADE ON UPDATE CASCADE,
  credential_id TEXT NOT NULL UNIQUE,
  public_key TEXT NOT NULL,
  label TEXT,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_user_passkeys_username ON user_passkeys (username);
