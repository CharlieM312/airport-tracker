-- Add TOTP (Microsoft/Yubico Authenticator) and WebAuthn (YubiKey/Passkey) columns to users
ALTER TABLE users ADD COLUMN totp_secret TEXT;
ALTER TABLE users ADD COLUMN totp_pending_secret TEXT;
ALTER TABLE users ADD COLUMN webauthn_credential_id TEXT;
ALTER TABLE users ADD COLUMN webauthn_public_key TEXT;
ALTER TABLE users ADD COLUMN webauthn_challenge TEXT;

-- Table to support multiple YubiKeys / Passkeys per user
CREATE TABLE IF NOT EXISTS user_passkeys (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT NOT NULL,
  credential_id TEXT NOT NULL UNIQUE,
  public_key TEXT NOT NULL,
  label TEXT,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_user_passkeys_username ON user_passkeys (username);
