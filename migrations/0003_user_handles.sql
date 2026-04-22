CREATE TABLE IF NOT EXISTS user_handles (
  user_id TEXT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
  username_norm TEXT NOT NULL,
  discriminator TEXT NOT NULL,
  active BOOLEAN NOT NULL DEFAULT true,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  deactivated_at TIMESTAMPTZ,
  PRIMARY KEY (user_id, created_at),
  CONSTRAINT chk_user_handles_username_norm_format CHECK (username_norm ~ '^[a-z0-9_]{3,20}$'),
  CONSTRAINT chk_user_handles_discriminator_format CHECK (discriminator ~ '^[0-9]{4}$')
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_user_handles_active_name_tag
  ON user_handles (username_norm, discriminator)
  WHERE active = true;

CREATE UNIQUE INDEX IF NOT EXISTS uq_user_handles_active_user
  ON user_handles (user_id)
  WHERE active = true;

WITH backfill AS (
  SELECT u.user_id,
         ('u_' || substr(replace(u.user_id, '-', ''), 1, 12)) AS username_norm,
         row_number() OVER (
           PARTITION BY ('u_' || substr(replace(u.user_id, '-', ''), 1, 12))
           ORDER BY u.user_id
         ) - 1 AS rn
  FROM users u
  WHERE NOT EXISTS (
    SELECT 1
    FROM user_handles h
    WHERE h.user_id = u.user_id AND h.active = true
  )
)
INSERT INTO user_handles (user_id, username_norm, discriminator, active, created_at)
SELECT user_id,
       username_norm,
       lpad((rn % 10000)::text, 4, '0') AS discriminator,
       true,
       now()
FROM backfill;
