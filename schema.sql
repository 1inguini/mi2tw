CREATE TABLE webhook (
  webhook_id INTEGER NOT NULL UNIQUE PRIMARY KEY,
  secret TEXT NOT NULL
);
CREATE TABLE twitter (
  twitter_id INTEGER NOT NULL UNIQUE PRIMARY KEY,
  twitter_username TEXT NOT NULL,
  twitter_name TEXT
);
CREATE TABLE twitter_token (
  twitter_token_id INTEGER NOT NULL UNIQUE PRIMARY KEY,
  twitter_id INTEGER NOT NULL,
  access_token TEXT,
  vaild_until INTEGER,
  refresh_token TEXT NOT NULL,
  FOREIGN KEY (twitter_id) REFERENCES twitter (twitter_id) ON UPDATE CASCADE ON DELETE CASCADE
);
CREATE TABLE webhook_to_twitter (
  webhook_id INTEGER NOT NULL,
  twitter_id INTEGER NOT NULL,
  FOREIGN KEY (webhook_id) REFERENCES webook (webhook_id) ON UPDATE CASCADE ON DELETE CASCADE,
  FOREIGN KEY (twitter_id) REFERENCES twitter (twitter_id) ON UPDATE CASCADE ON DELETE CASCADE
);