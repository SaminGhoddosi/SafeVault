-- SQLite schema; application initializes this automatically.
CREATE TABLE IF NOT EXISTS Users (
 UserID INTEGER PRIMARY KEY AUTOINCREMENT,
 Username TEXT NOT NULL UNIQUE,
 Email TEXT NOT NULL,
 PasswordHash TEXT NOT NULL,
 Role TEXT NOT NULL CHECK(Role IN ('admin','user'))
);
