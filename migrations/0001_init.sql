CREATE TABLE IF NOT EXISTS users (
  user_id TEXT PRIMARY KEY,
  identity_key_ed25519 TEXT NOT NULL,
  dh_key_x25519 TEXT NOT NULL,
  keyset_version INT NOT NULL DEFAULT 1,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS registration_nonces (
  user_id TEXT NOT NULL,
  nonce TEXT NOT NULL,
  signed_at TIMESTAMPTZ NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (user_id, nonce)
);

CREATE INDEX IF NOT EXISTS idx_registration_nonces_user_created
  ON registration_nonces (user_id, created_at);
