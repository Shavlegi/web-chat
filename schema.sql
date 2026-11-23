-- schema.sql — web-chat D1 სქემა (საცნობარო სრული სქემა).
-- წყარო: src/index.js-ში ensureSchema() ქმნის იგივე ცხრილებს
-- ლეიზი იდემპოტენტური მიგრაციებით (v1..v3). ეს ფაილი მხოლოდ
-- დოკუმენტაციისთვისაა და wrangler d1 execute-ით ხელით გასაშვებად.
-- schema_meta ინახავს, რომელი მიგრაციაა გაშვებული.

CREATE TABLE IF NOT EXISTS schema_meta (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
);

-- v1: მომხმარებლები + სესიები + rate limit-ები
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  is_admin INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS sessions (
  token_hash TEXT PRIMARY KEY,
  user_id INTEGER NOT NULL,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS rate_limits (
  key TEXT PRIMARY KEY,
  count INTEGER NOT NULL,
  window_start INTEGER NOT NULL
);

-- v2: ჩატები + წევრები
-- პირდაპირი (1:1) ჩატის title NULL-ია — სათაური თითოეული
-- მომხმარებლისთვის მეორე წევრის username-ია და კოდი ითვლის.
-- ჯგუფურ ჩატს title აუცილებლად აქვს.
CREATE TABLE IF NOT EXISTS chats (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  title TEXT,
  is_group INTEGER NOT NULL DEFAULT 0,
  created_by INTEGER NOT NULL,
  created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS chat_members (
  chat_id INTEGER NOT NULL,
  user_id INTEGER NOT NULL,
  last_read_at INTEGER NOT NULL DEFAULT 0,
  joined_at INTEGER NOT NULL,
  PRIMARY KEY (chat_id, user_id)
);

-- v3: შეტყობინებები
CREATE TABLE IF NOT EXISTS messages (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  chat_id INTEGER NOT NULL,
  user_id INTEGER NOT NULL,
  body TEXT NOT NULL,
  created_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_messages_chat_id ON messages (chat_id, id);
CREATE INDEX IF NOT EXISTS idx_chat_members_user ON chat_members (user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions (user_id);
