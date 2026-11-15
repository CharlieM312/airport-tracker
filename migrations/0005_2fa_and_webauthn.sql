-- Add TOTP (Microsoft/Yubico Authenticator) and WebAuthn (YubiKey/Passkey) columns to users
ALTER TABLE users ADD COLUMN totp_secret TEXT;
ALTER TABLE users ADD COLUMN webauthn_credential_id TEXT;
ALTER TABLE users ADD COLUMN webauthn_public_key TEXT;
ALTER TABLE users ADD COLUMN webauthn_challenge TEXT;
