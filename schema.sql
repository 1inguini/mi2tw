CREATE TABLE IF NOT EXISTS s256 (
  code_verifier TEXT NOT NULL UNIQUE PRIMARY KEY,
  code_challenge TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS webhook (
  webhook_id INTEGER NOT NULL UNIQUE PRIMARY KEY,
  secret TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS twitter (
  twitter_id TEXT NOT NULL UNIQUE PRIMARY KEY,
  twitter_username TEXT NOT NULL,
  twitter_name TEXT
);
CREATE TABLE IF NOT EXISTS twitter_token (
  twitter_id TEXT,
  access_token TEXT,
  valid_until INTEGER,
  refresh_token TEXT NOT NULL,
  FOREIGN KEY (twitter_id) REFERENCES twitter (twitter_id) ON UPDATE CASCADE ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS webhook_to_twitter (
  webhook_id INTEGER NOT NULL,
  twitter_id TEXT NOT NULL,
  FOREIGN KEY (webhook_id) REFERENCES webhook (webhook_id) ON UPDATE CASCADE ON DELETE CASCADE,
  FOREIGN KEY (twitter_id) REFERENCES twitter (twitter_id) ON UPDATE CASCADE ON DELETE CASCADE
);