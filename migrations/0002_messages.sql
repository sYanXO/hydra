CREATE TABLE IF NOT EXISTS messages (
  server_message_id TEXT PRIMARY KEY,
  to_user_id TEXT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
  from_user_id TEXT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
  message_id TEXT NOT NULL,
  envelope_json JSONB NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('pending','delivered')),
  received_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  delivered_at TIMESTAMPTZ,
  expires_at TIMESTAMPTZ NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_messages_pair_message_id
  ON messages (from_user_id, to_user_id, message_id);

CREATE INDEX IF NOT EXISTS idx_messages_to_status_received
  ON messages (to_user_id, status, received_at);

CREATE INDEX IF NOT EXISTS idx_messages_expires_at
  ON messages (expires_at);
