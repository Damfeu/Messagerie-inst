-- D-Send v2 — schéma SQLite (essai local)
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT NOT NULL UNIQUE,
    auth_hash TEXT NOT NULL,
    kdf_salt TEXT NOT NULL,
    public_key TEXT NOT NULL,
    enc_private_key TEXT NOT NULL,
    private_key_iv TEXT NOT NULL,
    color TEXT NOT NULL,
    created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sender_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    receiver_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    iv TEXT NOT NULL,
    ciphertext TEXT NOT NULL,
    kind TEXT NOT NULL CHECK (kind IN ('text','file')),
    created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_pair ON messages (sender_id, receiver_id, id);
CREATE INDEX IF NOT EXISTS idx_receiver ON messages (receiver_id, id);
CREATE TABLE IF NOT EXISTS login_attempts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    attempt_key TEXT NOT NULL,
    attempted_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_key ON login_attempts (attempt_key);
