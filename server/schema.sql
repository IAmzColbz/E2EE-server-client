-- User table
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL
);

-- Public keys for E2EE
CREATE TABLE IF NOT EXISTS public_keys (
    user_id INTEGER PRIMARY KEY,
    public_key TEXT NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users (id)
);

-- Chat requests to manage connections
CREATE TABLE IF NOT EXISTS chat_requests (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    requester_id INTEGER NOT NULL,
    requested_id INTEGER NOT NULL,
    status TEXT NOT NULL, -- 'pending', 'accepted', 'blocked'
    FOREIGN KEY (requester_id) REFERENCES users (id),
    FOREIGN KEY (requested_id) REFERENCES users (id),
    UNIQUE(requester_id, requested_id)
);

-- Messages table
CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sender_id INTEGER NOT NULL,
    recipient_id INTEGER NOT NULL,
    encrypted_blob TEXT NOT NULL,
    timestamp DATETIME NOT NULL,
    FOREIGN KEY (sender_id) REFERENCES users (id),
    FOREIGN KEY (recipient_id) REFERENCES users (id)
);
