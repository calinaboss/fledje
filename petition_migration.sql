-- Add petition table and votes table
CREATE TABLE IF NOT EXISTS petition (
    id TEXT PRIMARY KEY,
    count INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS petition_votes (
    voter_hash TEXT PRIMARY KEY,
    created_at INTEGER NOT NULL
);

-- Inizializza il contatore a 47 se non esiste
INSERT OR IGNORE INTO petition (id, count) VALUES ('fledje_haircut', 47);
