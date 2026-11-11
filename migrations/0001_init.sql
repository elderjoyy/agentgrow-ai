CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  email TEXT NOT NULL UNIQUE COLLATE NOCASE,
  password_hash TEXT NOT NULL,
  password_salt TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'user',
  plan TEXT NOT NULL DEFAULT 'free',
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS sessions (
  token_hash TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  expires_at INTEGER NOT NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS properties (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  title TEXT NOT NULL,
  bhk TEXT NOT NULL,
  price_value TEXT NOT NULL,
  price_unit TEXT NOT NULL,
  location TEXT NOT NULL,
  city TEXT NOT NULL,
  carpet_area TEXT NOT NULL,
  rera_number TEXT DEFAULT '',
  vastu_compliant INTEGER NOT NULL DEFAULT 0,
  amenities TEXT DEFAULT '',
  broker_name TEXT NOT NULL,
  broker_phone TEXT NOT NULL,
  image_key TEXT DEFAULT '',
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS campaigns (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  property_id TEXT,
  property_title TEXT NOT NULL,
  whatsapp_text TEXT NOT NULL,
  social_caption TEXT NOT NULL,
  reels_script TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS usage (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  month_key TEXT NOT NULL,
  generations INTEGER NOT NULL DEFAULT 0,
  UNIQUE(user_id, month_key),
  FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_properties_user ON properties(user_id, updated_at DESC);
CREATE INDEX IF NOT EXISTS idx_campaigns_user ON campaigns(user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_sessions_expiry ON sessions(expires_at);
