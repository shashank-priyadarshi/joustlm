package internal

import (
	"database/sql"
	"fmt"
	"time"

	"go.ssnk.in/joustlm/config"
	"go.ssnk.in/joustlm/logger"
	"go.ssnk.in/joustlm/schema/api"
	"go.ssnk.in/joustlm/schema/db"

	"github.com/google/uuid"
	_ "github.com/mattn/go-sqlite3"
)

type Dao struct {
	logger    *logger.Logger
	databases map[config.Tables]*sql.DB
}

func NewDao(logger *logger.Logger, conf *config.Database) *Dao {
	databases := make(map[config.Tables]*sql.DB)

	for key, dsn := range conf.DSN {
		db, err := sql.Open("sqlite3", dsn)
		if err != nil {
			logger.Error("Failed to connect to database", "error", err)
			return nil
		}

		databases[key] = db
	}

	return &Dao{
		logger:    logger,
		databases: databases,
	}
}

func (d *Dao) Close() error {
	for _, db := range d.databases {
		if err := db.Close(); err != nil {
			return err
		}
	}

	return nil
}

func (d *Dao) RunMigrations() error {
	migrations := db.GetMigrations()

	var dbConn *sql.DB
	for _, conn := range d.databases {
		dbConn = conn
		break
	}

	if dbConn == nil {
		return fmt.Errorf("no database connection available")
	}

	createMigrationsTable := `
	CREATE TABLE IF NOT EXISTS schema_migrations (
		version VARCHAR(255) PRIMARY KEY,
		applied_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
	);`

	if _, err := dbConn.Exec(createMigrationsTable); err != nil {
		return fmt.Errorf("failed to create migrations table: %w", err)
	}

	for _, migration := range migrations {
		var count int
		err := dbConn.QueryRow("SELECT COUNT(*) FROM schema_migrations WHERE version = ?", migration.Version).Scan(&count)
		if err != nil {
			return fmt.Errorf("failed to check migration status: %w", err)
		}

		if count > 0 {
			d.logger.Info("Migration already applied", "version", migration.Version)
			continue
		}

		d.logger.Info("Running migration", "version", migration.Version)
		if _, err := dbConn.Exec(migration.Up); err != nil {
			return fmt.Errorf("failed to run migration %s: %w", migration.Version, err)
		}

		if _, err := dbConn.Exec("INSERT INTO schema_migrations (version) VALUES (?)", migration.Version); err != nil {
			return fmt.Errorf("failed to record migration %s: %w", migration.Version, err)
		}

		d.logger.Info("Migration completed", "version", migration.Version)
	}

	d.logger.Info("All migrations completed successfully")
	return nil
}

func (d *Dao) GetLLMMetrics() (*api.Metrics, error) {
	d.logger.Debug("Starting LLM metrics retrieval")

	row := d.databases[config.TableAnalyses].QueryRow(GetLLMMetricsQuery)
	if err := row.Err(); err != nil {
		d.logger.Debug("Database error while getting LLM metrics", "error", err)
		d.logger.Error("Failed to get LLM metrics", "error", err)
		return nil, fmt.Errorf("failed to get LLM metrics: %w", err)
	}

	var metrics api.Metrics
	err := row.Scan(&metrics.Analyses, &metrics.Users, &metrics.TotalTexts, &metrics.AvgConfidence)
	if err != nil {
		d.logger.Debug("Error scanning LLM metrics row", "error", err)
		d.logger.Error("Failed to scan LLM metrics", "error", err)
		return nil, fmt.Errorf("failed to scan LLM metrics: %w", err)
	}

	return &metrics, nil
}

func (d *Dao) CreateAnalysis(analysis *db.Analysis) error {
	d.logger.Debug("Starting analysis creation", "user_id", analysis.UserID, "text_length", len(analysis.Text))

	now := time.Now()
	analysis.CreatedAt = now
	analysis.UpdatedAt = now

	_, err := d.databases[config.TableAnalyses].Exec(CreateAnalysisQuery,
		analysis.ID, analysis.UserID, analysis.Text, analysis.Title, analysis.Summary,
		analysis.Topics, analysis.Sentiment, analysis.Keywords, analysis.Confidence,
		analysis.CreatedAt, analysis.UpdatedAt)

	if err != nil {
		d.logger.Debug("Database error while creating analysis", "error", err, "user_id", analysis.UserID)
		d.logger.Error("Failed to create analysis", "error", err, "user_id", analysis.UserID)
		return fmt.Errorf("failed to create analysis: %w", err)
	}

	d.logger.Info("Analysis created successfully", "analysis_id", analysis.ID, "user_id", analysis.UserID)
	return nil
}

func (d *Dao) CreateUser(user *db.User) error {
	d.logger.Debug("Starting user creation", "username", user.Username, "user_id", user.ID)

	now := time.Now()
	user.CreatedAt = now
	user.UpdatedAt = now

	_, err := d.databases[config.TableUsers].Exec(CreateUserQuery,
		user.ID, user.Username, user.PasswordHash, user.SessionID, user.CreatedAt, user.UpdatedAt)

	if err != nil {
		d.logger.Debug("Database error while creating user", "error", err, "username", user.Username, "user_id", user.ID)
		d.logger.Error("Failed to create user", "error", err, "username", user.Username)
		return fmt.Errorf("failed to create user: %w", err)
	}

	d.logger.Info("User created successfully", "user_id", user.ID, "username", user.Username)
	return nil
}

func (d *Dao) GetUserByUsername(username string) (*db.User, error) {
	d.logger.Debug("Starting user lookup by username", "username", username)

	user := &db.User{}
	err := d.databases[config.TableUsers].QueryRow(GetUserByUsernameQuery, username).Scan(
		&user.ID, &user.Username, &user.PasswordHash, &user.SessionID, &user.CreatedAt, &user.UpdatedAt)

	if err != nil {
		if err == sql.ErrNoRows {
			d.logger.Debug("User not found", "username", username)
			return nil, nil
		}
		d.logger.Debug("Database error while getting user by username", "error", err, "username", username)
		d.logger.Error("Failed to get user by username", "error", err, "username", username)
		return nil, fmt.Errorf("failed to get user by username: %w", err)
	}

	d.logger.Debug("User found", "username", username, "user_id", user.ID)
	return user, nil
}

func (d *Dao) GetUserBySessionID(sessionID string) (*db.User, error) {
	d.logger.Debug("Starting user lookup by session ID", "session_id", sessionID)

	user := &db.User{}
	err := d.databases[config.TableUsers].QueryRow(GetUserBySessionIDQuery, sessionID).Scan(
		&user.ID, &user.Username, &user.PasswordHash, &user.SessionID, &user.CreatedAt, &user.UpdatedAt)

	if err != nil {
		if err == sql.ErrNoRows {
			d.logger.Debug("Session not found", "session_id", sessionID)
			return nil, nil
		}
		d.logger.Debug("Database error while getting user by session ID", "error", err, "session_id", sessionID)
		d.logger.Error("Failed to get user by session ID", "error", err, "session_id", sessionID)
		return nil, fmt.Errorf("failed to get user by session ID: %w", err)
	}

	d.logger.Debug("Session found", "session_id", sessionID, "user_id", user.ID)
	return user, nil
}

func (d *Dao) UpdateUserSession(userID string, sessionID string) error {
	d.logger.Debug("Starting user session update", "user_id", userID, "session_id", sessionID)

	result, err := d.databases[config.TableUsers].Exec(UpdateUserSessionQuery, sessionID, time.Now(), userID)

	if err != nil {
		d.logger.Debug("Database error while updating user session", "error", err, "user_id", userID, "session_id", sessionID)
		d.logger.Error("Failed to update user session", "error", err, "user_id", userID)
		return fmt.Errorf("failed to update user session: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		d.logger.Debug("Error getting rows affected", "error", err, "user_id", userID)
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		d.logger.Debug("User not found for session update", "user_id", userID)
		return fmt.Errorf("user not found")
	}

	d.logger.Info("User session updated successfully", "user_id", userID, "session_id", sessionID)
	return nil
}

func (d *Dao) ClearUserSession(userID uuid.UUID) error {
	d.logger.Debug("Starting user session clear", "user_id", userID)

	result, err := d.databases[config.TableUsers].Exec(ClearUserSessionQuery, time.Now(), userID)

	if err != nil {
		d.logger.Debug("Database error while clearing user session", "error", err, "user_id", userID)
		d.logger.Error("Failed to clear user session", "error", err, "user_id", userID)
		return fmt.Errorf("failed to clear user session: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		d.logger.Debug("Error getting rows affected", "error", err, "user_id", userID)
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		d.logger.Debug("User not found for session clear", "user_id", userID)
		return fmt.Errorf("user not found")
	}

	d.logger.Info("User session cleared successfully", "user_id", userID)
	return nil
}

func (d *Dao) GetAnalysisByID(id uuid.UUID) (*db.Analysis, error) {
	d.logger.Debug("Starting analysis lookup by ID", "analysis_id", id)

	analysis := &db.Analysis{}
	err := d.databases[config.TableAnalyses].QueryRow(GetAnalysisByIDQuery, id).Scan(
		&analysis.ID, &analysis.UserID, &analysis.Text, &analysis.Title, &analysis.Summary,
		&analysis.Topics, &analysis.Sentiment, &analysis.Keywords, &analysis.Confidence,
		&analysis.CreatedAt, &analysis.UpdatedAt)

	if err != nil {
		if err == sql.ErrNoRows {
			d.logger.Debug("Analysis not found", "analysis_id", id)
			return nil, nil
		}
		d.logger.Debug("Database error while getting analysis by ID", "error", err, "analysis_id", id)
		d.logger.Error("Failed to get analysis by ID", "error", err, "analysis_id", id)
		return nil, fmt.Errorf("failed to get analysis by ID: %w", err)
	}

	d.logger.Debug("Analysis found", "analysis_id", id, "user_id", analysis.UserID)
	return analysis, nil
}

func (d *Dao) GetAnalysesByUserID(userID uuid.UUID, page, limit int) ([]db.Analysis, int, error) {
	d.logger.Debug("Starting analysis retrieval by user ID", "user_id", userID, "page", page, "limit", limit)

	offset := (page - 1) * limit
	var totalCount int

	err := d.databases[config.TableAnalyses].QueryRow(GetAnalysesByUserIDCountQuery, userID.String()).Scan(&totalCount)
	if err != nil {
		d.logger.Debug("Database error while getting analysis count", "error", err, "user_id", userID)
		d.logger.Error("Failed to get analysis count", "error", err, "user_id", userID)
		return nil, 0, fmt.Errorf("failed to get analysis count: %w", err)
	}

	rows, err := d.databases[config.TableAnalyses].Query(GetAnalysesByUserIDQuery, userID.String(), limit, offset)
	if err != nil {
		d.logger.Debug("Database error while getting analyses", "error", err, "user_id", userID)
		d.logger.Error("Failed to get analyses", "error", err, "user_id", userID)
		return nil, 0, fmt.Errorf("failed to get analyses: %w", err)
	}
	defer rows.Close()

	var analyses []db.Analysis
	for rows.Next() {
		var analysis db.Analysis
		err := rows.Scan(&analysis.ID, &analysis.UserID, &analysis.Text, &analysis.Title, &analysis.Summary,
			&analysis.Topics, &analysis.Sentiment, &analysis.Keywords, &analysis.Confidence,
			&analysis.CreatedAt, &analysis.UpdatedAt)
		if err != nil {
			d.logger.Debug("Error scanning analysis row", "error", err)
			d.logger.Error("Failed to scan analysis", "error", err)
			return nil, 0, fmt.Errorf("failed to scan analysis: %w", err)
		}

		analyses = append(analyses, analysis)
	}

	if err = rows.Err(); err != nil {
		d.logger.Debug("Error iterating analysis rows", "error", err)
		d.logger.Error("Error iterating analyses", "error", err)
		return nil, 0, fmt.Errorf("error iterating analyses: %w", err)
	}

	d.logger.Debug("Analyses retrieved successfully", "user_id", userID, "count", len(analyses), "total_count", totalCount)
	return analyses, totalCount, nil
}

func (d *Dao) UpdateAnalysis(analysis *db.Analysis) error {
	d.logger.Debug("Starting analysis update", "analysis_id", analysis.ID, "user_id", analysis.UserID)

	analysis.UpdatedAt = time.Now()

	result, err := d.databases[config.TableAnalyses].Exec(UpdateAnalysisQuery,
		analysis.Title, analysis.Summary, analysis.Topics, analysis.Sentiment,
		analysis.Keywords, analysis.Confidence, analysis.UpdatedAt, analysis.ID)

	if err != nil {
		d.logger.Debug("Database error while updating analysis", "error", err, "analysis_id", analysis.ID)
		d.logger.Error("Failed to update analysis", "error", err, "analysis_id", analysis.ID)
		return fmt.Errorf("failed to update analysis: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		d.logger.Debug("Error getting rows affected", "error", err, "analysis_id", analysis.ID)
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		d.logger.Debug("Analysis not found for update", "analysis_id", analysis.ID)
		return fmt.Errorf("analysis not found")
	}

	d.logger.Info("Analysis updated successfully", "analysis_id", analysis.ID)
	return nil
}

func (d *Dao) DeleteAnalysis(id uuid.UUID) error {
	d.logger.Debug("Starting analysis deletion", "analysis_id", id)

	result, err := d.databases[config.TableAnalyses].Exec(DeleteAnalysisQuery, id)

	if err != nil {
		d.logger.Debug("Database error while deleting analysis", "error", err, "analysis_id", id)
		d.logger.Error("Failed to delete analysis", "error", err, "analysis_id", id)
		return fmt.Errorf("failed to delete analysis: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		d.logger.Debug("Error getting rows affected", "error", err, "analysis_id", id)
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		d.logger.Debug("Analysis not found for deletion", "analysis_id", id)
		return fmt.Errorf("analysis not found")
	}

	d.logger.Info("Analysis deleted successfully", "analysis_id", id)
	return nil
}

func (d *Dao) SearchAnalyses(topic, keyword, sentiment string, page, limit int) ([]db.Analysis, int, error) {
	d.logger.Debug("Starting analysis search", "topic", topic, "keyword", keyword, "sentiment", sentiment, "page", page, "limit", limit)

	offset := (page - 1) * limit
	var totalCount int

	// Build dynamic query based on search parameters
	query := SearchAnalysesQuery
	countQuery := SearchAnalysesCountQuery
	args := []interface{}{}
	countArgs := []interface{}{}

	if topic != "" {
		query += " AND JSON_EXTRACT(topics, '$') LIKE ?"
		countQuery += " AND JSON_EXTRACT(topics, '$') LIKE ?"
		args = append(args, "%"+topic+"%")
		countArgs = append(countArgs, "%"+topic+"%")
	}

	if keyword != "" {
		query += " AND JSON_EXTRACT(keywords, '$') LIKE ?"
		countQuery += " AND JSON_EXTRACT(keywords, '$') LIKE ?"
		args = append(args, "%"+keyword+"%")
		countArgs = append(countArgs, "%"+keyword+"%")
	}

	if sentiment != "" {
		query += " AND sentiment = ?"
		countQuery += " AND sentiment = ?"
		args = append(args, sentiment)
		countArgs = append(countArgs, sentiment)
	}

	query += " ORDER BY created_at DESC LIMIT ? OFFSET ?"
	args = append(args, limit, offset)

	err := d.databases[config.TableAnalyses].QueryRow(countQuery, countArgs...).Scan(&totalCount)
	if err != nil {
		d.logger.Debug("Database error while getting search count", "error", err)
		d.logger.Error("Failed to get search count", "error", err)
		return nil, 0, fmt.Errorf("failed to get search count: %w", err)
	}

	rows, err := d.databases[config.TableAnalyses].Query(query, args...)
	if err != nil {
		d.logger.Debug("Database error while searching analyses", "error", err)
		d.logger.Error("Failed to search analyses", "error", err)
		return nil, 0, fmt.Errorf("failed to search analyses: %w", err)
	}
	defer rows.Close()

	var analyses []db.Analysis
	for rows.Next() {
		var analysis db.Analysis
		err := rows.Scan(&analysis.ID, &analysis.UserID, &analysis.Text, &analysis.Title, &analysis.Summary,
			&analysis.Topics, &analysis.Sentiment, &analysis.Keywords, &analysis.Confidence,
			&analysis.CreatedAt, &analysis.UpdatedAt)
		if err != nil {
			d.logger.Debug("Error scanning analysis row", "error", err)
			d.logger.Error("Failed to scan analysis", "error", err)
			return nil, 0, fmt.Errorf("failed to scan analysis: %w", err)
		}

		analyses = append(analyses, analysis)
	}

	if err = rows.Err(); err != nil {
		d.logger.Debug("Error iterating analysis rows", "error", err)
		d.logger.Error("Error iterating analyses", "error", err)
		return nil, 0, fmt.Errorf("error iterating analyses: %w", err)
	}

	d.logger.Debug("Analyses search completed successfully", "count", len(analyses), "total_count", totalCount)
	return analyses, totalCount, nil
}
