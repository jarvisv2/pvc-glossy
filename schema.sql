CREATE TABLE IF NOT EXISTS users (
  email TEXT PRIMARY KEY,
  name TEXT,
  status TEXT NOT NULL DEFAULT 'pending',
  created_at TEXT,
  last_login TEXT
);
CREATE TABLE IF NOT EXISTS logins (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  email TEXT, name TEXT, result TEXT, ip TEXT, country TEXT, ua TEXT, ts TEXT
);
