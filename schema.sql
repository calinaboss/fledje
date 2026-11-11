-- Schema per Cloudflare D1 Database (SQLite)
-- Da eseguire con: wrangler d1 execute fledje-db --file=schema.sql (oppure da dashboard Cloudflare D1)

CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    username TEXT UNIQUE NOT NULL COLLATE NOCASE,
    password_hash TEXT NOT NULL,
    salt TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    last_login INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS scores (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    username TEXT NOT NULL,
    score INTEGER NOT NULL,
    game_mode TEXT NOT NULL,
    boss_defeated INTEGER DEFAULT 0,
    created_at INTEGER NOT NULL,
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_scores_game_score ON scores(game_mode, score DESC);
CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
