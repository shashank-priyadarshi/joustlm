package db

const CreateAnalysisTable = `
CREATE TABLE IF NOT EXISTS analyses (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    text TEXT NOT NULL,
    title TEXT,
    summary TEXT,
    topics TEXT,
    sentiment TEXT,
    keywords TEXT,
    confidence REAL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);
`

type Migration struct {
	Version string
	Up      string
	Down    string
}

func GetMigrations() []Migration {
	return []Migration{
		{
			Version: "001_create_users_table",
			Up: `
CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    username VARCHAR(50) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    session_id VARCHAR(255),
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
CREATE INDEX IF NOT EXISTS idx_users_session_id ON users(session_id);
CREATE INDEX IF NOT EXISTS idx_users_created_at ON users(created_at);
`,
			Down: `DROP TABLE IF EXISTS users;`,
		},
		{
			Version: "002_create_analyses_table",
			Up: `
CREATE TABLE IF NOT EXISTS analyses (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    text TEXT NOT NULL,
    title TEXT,
    summary TEXT,
    topics TEXT,
    sentiment TEXT,
    keywords TEXT,
    confidence REAL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_analyses_user_id ON analyses(user_id);
CREATE INDEX IF NOT EXISTS idx_analyses_created_at ON analyses(created_at);
CREATE INDEX IF NOT EXISTS idx_analyses_sentiment ON analyses(sentiment);
CREATE INDEX IF NOT EXISTS idx_analyses_topics ON analyses(topics);
CREATE INDEX IF NOT EXISTS idx_analyses_keywords ON analyses(keywords);
`,
			Down: `DROP TABLE IF EXISTS analyses;`,
		},
	}
}
