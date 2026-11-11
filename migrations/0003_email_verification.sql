ALTER TABLE users ADD COLUMN phone TEXT NOT NULL DEFAULT '';
ALTER TABLE users ADD COLUMN email_verified INTEGER NOT NULL DEFAULT 1;

CREATE TABLE IF NOT EXISTS pending_registrations (
  email TEXT PRIMARY KEY COLLATE NOCASE,
  name TEXT NOT NULL,
  phone TEXT NOT NULL,
  password_hash TEXT NOT NULL,
  password_salt TEXT NOT NULL,
  code_hash TEXT NOT NULL,
  expires_at INTEGER NOT NULL,
  attempts INTEGER NOT NULL DEFAULT 0,
  last_sent_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_pending_registrations_expiry ON pending_registrations(expires_at);
