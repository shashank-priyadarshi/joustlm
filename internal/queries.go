package internal

var (
	GetLLMMetricsQuery = `SELECT
		COUNT(DISTINCT analyses.id) as analyses,
		COUNT(DISTINCT users.id) as users,
		COUNT(analyses.id) as total_texts,
		COALESCE(AVG(analyses.confidence), 0) as avg_confidence
		FROM analyses
		JOIN users ON analyses.user_id = users.id`

	CreateUserQuery = `INSERT INTO users (id, username, password_hash, session_id, created_at, updated_at)
					   VALUES (?, ?, ?, ?, ?, ?)`

	GetUserByUsernameQuery = `SELECT id, username, password_hash, session_id, created_at, updated_at
							  FROM users WHERE username = ?`

	GetUserBySessionIDQuery = `SELECT id, username, password_hash, session_id, created_at, updated_at
							   FROM users WHERE session_id = ?`

	UpdateUserSessionQuery = `UPDATE users SET session_id = ?, updated_at = ? WHERE id = ?`

	ClearUserSessionQuery = `UPDATE users SET session_id = NULL, updated_at = ? WHERE id = ?`

	CreateAnalysisQuery = `INSERT INTO analyses (id, user_id, text, title, summary, topics, sentiment, keywords, confidence, created_at, updated_at)
						   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`

	GetAnalysisByIDQuery = `SELECT id, user_id, text, title, summary, topics, sentiment, keywords, confidence, created_at, updated_at
							FROM analyses WHERE id = ?`

	GetAnalysesByUserIDCountQuery = `SELECT COUNT(*) FROM analyses WHERE user_id = ?`

	GetAnalysesByUserIDQuery = `SELECT id, user_id, text, title, summary, topics, sentiment, keywords, confidence, created_at, updated_at
								FROM analyses WHERE user_id = ?
								ORDER BY created_at DESC
								LIMIT ? OFFSET ?`

	UpdateAnalysisQuery = `UPDATE analyses SET title = ?, summary = ?, topics = ?, sentiment = ?, keywords = ?, confidence = ?, updated_at = ?
						  WHERE id = ?`

	DeleteAnalysisQuery = `DELETE FROM analyses WHERE id = ?`

	SearchAnalysesQuery = `SELECT id, user_id, text, title, summary, topics, sentiment, keywords, confidence, created_at, updated_at
						   FROM analyses WHERE 1=1`

	SearchAnalysesCountQuery = `SELECT COUNT(*) FROM analyses WHERE 1=1`
)
