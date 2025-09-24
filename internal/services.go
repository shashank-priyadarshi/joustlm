package internal

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"math"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"go.ssnk.in/joustlm/config"
	"go.ssnk.in/joustlm/logger"
	"go.ssnk.in/joustlm/pkg"
	"go.ssnk.in/joustlm/schema/api"
	"go.ssnk.in/joustlm/schema/db"
)

type Service struct {
	logger *logger.Logger
	dao    *Dao
	config *config.Security
}

func NewService(logger *logger.Logger, config *config.Security, dao *Dao) *Service {
	return &Service{
		logger: logger,
		dao:    dao,
		config: config,
	}
}

func (s *Service) GetLLMMetrics() (*api.MetricsResponse, error) {
	s.logger.Debug("Getting LLM metrics")

	metrics, err := s.dao.GetLLMMetrics()
	if err != nil {
		s.logger.Error("Failed to get LLM metrics", "error", err)
		return nil, fmt.Errorf("failed to get LLM metrics: %w", err)
	}

	return &api.MetricsResponse{
		Metrics: []api.Metrics{*metrics},
	}, nil
}

func (s *Service) ExtractKnowledge(req *api.LLMAnalysisRequest, userID uuid.UUID) (*api.LLMAnalysisResponse, error) {
	s.logger.Debug("Starting LLM knowledge extraction", "user_id", userID, "text_length", len(req.Text))

	if req.Text == "" {
		s.logger.Debug("Empty text provided for analysis")
		return nil, fmt.Errorf("text cannot be empty")
	}

	// Validate text input
	if err := pkg.ValidateText(req.Text); err != nil {
		s.logger.Debug("Text validation failed", "error", err)
		return nil, fmt.Errorf("text validation failed: %w", err)
	}

	// Preprocess text
	processedText := pkg.PreprocessText(req.Text)

	// Create LLM client (using mock for now, can be configured to use real LLM)
	var llmClient pkg.LLMClient
	// TODO: Configure based on environment or config
	// if s.config.LLM.APIKey != "" {
	//     llmClient = pkg.NewOpenAIClient(s.config.LLM.APIKey, s.config.LLM.Model)
	// } else {
		llmClient = pkg.NewMockLLMClient()
	// }

	// Analyze text with LLM
	response, err := llmClient.AnalyzeText(processedText)
	if err != nil {
		s.logger.Error("LLM analysis failed", "error", err, "user_id", userID)
		return nil, fmt.Errorf("LLM analysis failed: %w", err)
	}

	// Validate LLM response
	if err := pkg.ValidateSummary(response.Summary); err != nil {
		s.logger.Debug("Summary validation failed", "error", err)
		response.Summary = "Analysis completed successfully."
	}

	if err := pkg.ValidateTopics(response.Topics); err != nil {
		s.logger.Debug("Topics validation failed", "error", err)
		response.Topics = []string{"general", "content", "analysis"}
	}

	if err := pkg.ValidateKeywords(response.Keywords); err != nil {
		s.logger.Debug("Keywords validation failed", "error", err)
		response.Keywords = pkg.ExtractKeywords(processedText)
	}

	if err := pkg.ValidateSentiment(response.Sentiment); err != nil {
		s.logger.Debug("Sentiment validation failed", "error", err)
		response.Sentiment = "neutral"
	}

	if err := pkg.ValidateConfidence(response.Confidence); err != nil {
		s.logger.Debug("Confidence validation failed", "error", err)
		response.Confidence = 0.8
	}

	if err := pkg.ValidateTitle(response.Title); err != nil {
		s.logger.Debug("Title validation failed", "error", err)
		response.Title = "Untitled Analysis"
	}

	// Generate unique ID and timestamp
	analysisID := uuid.New()
	now := time.Now()
	response.ID = analysisID
	response.CreatedAt = now.Format(time.RFC3339)

	// Store analysis in database
	analysis := &db.Analysis{
		ID:         analysisID,
		UserID:     userID,
		Text:       req.Text,
		Title:      response.Title,
		Summary:    response.Summary,
		Topics:     response.Topics,
		Sentiment:  response.Sentiment,
		Keywords:   response.Keywords,
		Confidence: response.Confidence,
	}

	err = s.dao.CreateAnalysis(analysis)
	if err != nil {
		s.logger.Error("Failed to store analysis", "error", err, "analysis_id", analysisID)
		return nil, fmt.Errorf("failed to store analysis: %w", err)
	}

	s.logger.Info("Knowledge extraction completed", "analysis_id", analysisID, "user_id", userID)
	return response, nil
}

func (s *Service) SignupUser(req *api.SignupRequest) (*api.SignupResponse, error) {
	s.logger.Debug("Starting user signup", "username", req.Username)

	existingUser, err := s.dao.GetUserByUsername(req.Username)
	if err != nil {
		s.logger.Debug("Database error while checking existing user", "error", err, "username", req.Username)
		s.logger.Error("Failed to check existing user", "error", err, "username", req.Username)
		return nil, fmt.Errorf("failed to check existing user: %w", err)
	}

	if existingUser != nil {
		s.logger.Debug("Username already exists", "username", req.Username)
		return nil, fmt.Errorf("username already exists")
	}

	hashedPassword := s.hashPassword(req.Password)
	sessionID := s.generateSecureRandomString(32)
	user := &db.User{
		ID:           uuid.New(),
		Username:     req.Username,
		PasswordHash: string(hashedPassword),
		SessionID:    sql.NullString{String: sessionID, Valid: true},
	}

	err = s.dao.CreateUser(user)
	if err != nil {
		s.logger.Debug("Database error while creating user", "error", err, "username", req.Username, "user_id", user.ID)
		s.logger.Error("Failed to create user", "error", err, "username", req.Username)
		return nil, fmt.Errorf("failed to create user: %w", err)
	}
	token := s.generateJWT(user.ID.String())
	refreshToken := s.generateRefreshToken()
	expiresAt := time.Now().Add(time.Duration(s.config.TokenExpiry) * time.Hour).Format(time.RFC3339)

	s.logger.Info("User signed up successfully", "user_id", user.ID, "username", user.Username)

	return &api.SignupResponse{
		Token:        token,
		RefreshToken: refreshToken,
		ExpiresAt:    expiresAt,
	}, nil
}

func (s *Service) LoginUser(req *api.LoginRequest) (*api.LoginResponse, error) {
	s.logger.Debug("Starting user login", "username", req.Username)

	user, err := s.dao.GetUserByUsername(req.Username)
	if err != nil {
		s.logger.Debug("Database error while getting user", "error", err, "username", req.Username)
		s.logger.Error("Failed to get user", "error", err, "username", req.Username)
		return nil, fmt.Errorf("failed to get user: %w", err)
	}

	if user == nil {
		s.logger.Debug("User not found", "username", req.Username)
		return nil, fmt.Errorf("invalid credentials")
	}
	if user.PasswordHash != s.hashPassword(req.Password) {
		s.logger.Debug("Password mismatch", "username", req.Username)
		s.logger.Error("Invalid password", "username", req.Username)
		return nil, fmt.Errorf("invalid credentials")
	}
	sessionID := s.generateSecureRandomString(32)
	err = s.dao.UpdateUserSession(user.ID.String(), sessionID)
	if err != nil {
		s.logger.Debug("Database error while updating user session", "error", err, "user_id", user.ID, "session_id", sessionID)
		s.logger.Error("Failed to update user session", "error", err, "user_id", user.ID)
		return nil, fmt.Errorf("failed to update user session: %w", err)
	}
	token := s.generateJWT(user.ID.String())
	refreshToken := s.generateRefreshToken()
	expiresAt := time.Now().Add(time.Duration(s.config.TokenExpiry) * time.Hour).Format(time.RFC3339)

	s.logger.Info("User logged in successfully", "user_id", user.ID, "username", user.Username)

	return &api.LoginResponse{
		Token:        token,
		RefreshToken: refreshToken,
		ExpiresAt:    expiresAt,
	}, nil
}

func (s *Service) LogoutUser(token string) error {
	s.logger.Debug("Starting user logout", "token_length", len(token))

	userID, err := s.validateJWT(token)
	if err != nil {
		s.logger.Debug("JWT validation failed", "error", err, "token_length", len(token))
		s.logger.Error("Failed to validate JWT token", "error", err)
		return fmt.Errorf("invalid token: %w", err)
	}
	s.logger.Debug("JWT validated successfully", "user_id", userID)

	err = s.dao.ClearUserSession(userID)
	if err != nil {
		s.logger.Debug("Database error while clearing user session", "error", err, "user_id", userID)
		s.logger.Error("Failed to clear user session", "error", err, "user_id", userID)
		return fmt.Errorf("failed to clear user session: %w", err)
	}

	s.logger.Info("User logged out successfully", "user_id", userID)
	return nil
}

func (s *Service) ValidateSession(sessionID string) (*db.User, error) {
	s.logger.Debug("Starting session validation", "session_id", sessionID)

	user, err := s.dao.GetUserBySessionID(sessionID)
	if err != nil {
		s.logger.Debug("Database error while validating session", "error", err, "session_id", sessionID)
		s.logger.Error("Failed to validate session", "error", err, "session_id", sessionID)
		return nil, fmt.Errorf("failed to validate session: %w", err)
	}

	if user == nil {
		s.logger.Debug("Session not found or invalid", "session_id", sessionID)
		return nil, fmt.Errorf("invalid session")
	}

	return user, nil
}

func (s *Service) GetExtractionResult(id uuid.UUID, userID uuid.UUID) (*api.LLMAnalysisResponse, error) {
	s.logger.Debug("Getting extraction result", "analysis_id", id, "user_id", userID)

	analysis, err := s.dao.GetAnalysisByID(id)
	if err != nil {
		s.logger.Error("Failed to get analysis", "error", err, "analysis_id", id)
		return nil, fmt.Errorf("failed to get analysis: %w", err)
	}

	if analysis == nil {
		s.logger.Debug("Analysis not found", "analysis_id", id)
		return nil, fmt.Errorf("analysis not found")
	}

	// Check if user has access to this analysis
	if analysis.UserID != userID {
		s.logger.Debug("Access denied to analysis", "analysis_id", id, "user_id", userID)
		return nil, fmt.Errorf("access denied")
	}

	response := &api.LLMAnalysisResponse{
		ID:         analysis.ID,
		Text:       analysis.Text,
		Title:      analysis.Title,
		Summary:    analysis.Summary,
		Topics:     analysis.Topics,
		Sentiment:  analysis.Sentiment,
		Keywords:   analysis.Keywords,
		Confidence: analysis.Confidence,
		CreatedAt:  analysis.CreatedAt.Format(time.RFC3339),
	}

	s.logger.Debug("Extraction result retrieved", "analysis_id", id, "user_id", userID)
	return response, nil
}

func (s *Service) GetKnowledgeEntries(userID uuid.UUID, page, limit int) (*api.GetKnowledgeResponse, error) {
	s.logger.Debug("Starting knowledge entries retrieval", "user_id", userID, "page", page, "limit", limit)

	analyses, totalCount, err := s.dao.GetAnalysesByUserID(userID, page, limit)
	if err != nil {
		s.logger.Debug("Database error while getting analyses", "error", err, "user_id", userID, "page", page, "limit", limit)
		s.logger.Error("Failed to get analyses", "error", err, "user_id", userID)
		return nil, fmt.Errorf("failed to get analyses: %w", err)
	}

	knowledgeEntries := make([]api.KnowledgeBaseEntry, 0, len(analyses))
	for _, analysis := range analyses {
		knowledgeEntries = append(knowledgeEntries, api.KnowledgeBaseEntry{
			ID:         analysis.ID,
			UserID:     analysis.UserID,
			Text:       analysis.Text,
			Title:      analysis.Title,
			Summary:    analysis.Summary,
			Topics:     analysis.Topics,
			Sentiment:  analysis.Sentiment,
			Keywords:   analysis.Keywords,
			Confidence: analysis.Confidence,
			CreatedAt:  analysis.CreatedAt.Format(time.RFC3339),
			UpdatedAt:  analysis.UpdatedAt.Format(time.RFC3339),
		})
	}

	var totalPages int
	if limit <= 0 {
		totalPages = 1
	} else {
		totalPages = int(math.Ceil(float64(totalCount) / float64(limit)))
		if totalPages == 0 {
			totalPages = 1
		}
	}

	return &api.GetKnowledgeResponse{
		Knowledge:   knowledgeEntries,
		CurrentPage: page,
		TotalPages:  totalPages,
		TotalCount:  totalCount,
	}, nil
}

func (s *Service) CreateKnowledgeEntry(req *api.CreateKnowledgeRequest, userID uuid.UUID) (*api.KnowledgeBaseEntry, error) {
	s.logger.Debug("Starting knowledge entry creation", "user_id", userID)

	// Validate input data
	if err := pkg.ValidateText(req.Text); err != nil {
		s.logger.Debug("Text validation failed", "error", err)
		return nil, fmt.Errorf("text validation failed: %w", err)
	}

	if err := pkg.ValidateSummary(req.Summary); err != nil {
		s.logger.Debug("Summary validation failed", "error", err)
		return nil, fmt.Errorf("summary validation failed: %w", err)
	}

	if err := pkg.ValidateTopics(req.Topics); err != nil {
		s.logger.Debug("Topics validation failed", "error", err)
		return nil, fmt.Errorf("topics validation failed: %w", err)
	}

	if err := pkg.ValidateKeywords(req.Keywords); err != nil {
		s.logger.Debug("Keywords validation failed", "error", err)
		return nil, fmt.Errorf("keywords validation failed: %w", err)
	}

	if err := pkg.ValidateSentiment(req.Sentiment); err != nil {
		s.logger.Debug("Sentiment validation failed", "error", err)
		return nil, fmt.Errorf("sentiment validation failed: %w", err)
	}

	if err := pkg.ValidateConfidence(req.Confidence); err != nil {
		s.logger.Debug("Confidence validation failed", "error", err)
		return nil, fmt.Errorf("confidence validation failed: %w", err)
	}

	if err := pkg.ValidateTitle(req.Title); err != nil {
		s.logger.Debug("Title validation failed", "error", err)
		return nil, fmt.Errorf("title validation failed: %w", err)
	}

	analysisID := uuid.New()
	now := time.Now()

	analysis := &db.Analysis{
		ID:         analysisID,
		UserID:     userID,
		Text:       req.Text,
		Title:      req.Title,
		Summary:    req.Summary,
		Topics:     req.Topics,
		Sentiment:  req.Sentiment,
		Keywords:   req.Keywords,
		Confidence: req.Confidence,
	}

	err := s.dao.CreateAnalysis(analysis)
	if err != nil {
		s.logger.Error("Failed to create knowledge entry", "error", err, "analysis_id", analysisID)
		return nil, fmt.Errorf("failed to create knowledge entry: %w", err)
	}

	entry := &api.KnowledgeBaseEntry{
		ID:         analysisID,
		UserID:     userID,
		Text:       req.Text,
		Title:      req.Title,
		Summary:    req.Summary,
		Topics:     req.Topics,
		Sentiment:  req.Sentiment,
		Keywords:   req.Keywords,
		Confidence: req.Confidence,
		CreatedAt:  now.Format(time.RFC3339),
		UpdatedAt:  now.Format(time.RFC3339),
	}

	s.logger.Info("Knowledge entry created successfully", "analysis_id", analysisID, "user_id", userID)
	return entry, nil
}

func (s *Service) UpdateKnowledgeEntry(id uuid.UUID, req *api.UpdateKnowledgeRequest, userID uuid.UUID) (*api.KnowledgeBaseEntry, error) {
	s.logger.Debug("Starting knowledge entry update", "analysis_id", id, "user_id", userID)

	analysis, err := s.dao.GetAnalysisByID(id)
	if err != nil {
		s.logger.Error("Failed to get analysis for update", "error", err, "analysis_id", id)
		return nil, fmt.Errorf("failed to get analysis: %w", err)
	}

	if analysis == nil {
		s.logger.Debug("Analysis not found", "analysis_id", id)
		return nil, fmt.Errorf("analysis not found")
	}

	// Check if user has access to this analysis
	if analysis.UserID != userID {
		s.logger.Debug("Access denied to analysis", "analysis_id", id, "user_id", userID)
		return nil, fmt.Errorf("access denied")
	}

	// Update fields if provided with validation
	if req.Title != "" {
		if err := pkg.ValidateTitle(req.Title); err != nil {
			s.logger.Debug("Title validation failed", "error", err)
			return nil, fmt.Errorf("title validation failed: %w", err)
		}
		analysis.Title = req.Title
	}
	if req.Summary != "" {
		if err := pkg.ValidateSummary(req.Summary); err != nil {
			s.logger.Debug("Summary validation failed", "error", err)
			return nil, fmt.Errorf("summary validation failed: %w", err)
		}
		analysis.Summary = req.Summary
	}
	if len(req.Topics) > 0 {
		if err := pkg.ValidateTopics(req.Topics); err != nil {
			s.logger.Debug("Topics validation failed", "error", err)
			return nil, fmt.Errorf("topics validation failed: %w", err)
		}
		analysis.Topics = req.Topics
	}
	if req.Sentiment != "" {
		if err := pkg.ValidateSentiment(req.Sentiment); err != nil {
			s.logger.Debug("Sentiment validation failed", "error", err)
			return nil, fmt.Errorf("sentiment validation failed: %w", err)
		}
		analysis.Sentiment = req.Sentiment
	}
	if len(req.Keywords) > 0 {
		if err := pkg.ValidateKeywords(req.Keywords); err != nil {
			s.logger.Debug("Keywords validation failed", "error", err)
			return nil, fmt.Errorf("keywords validation failed: %w", err)
		}
		analysis.Keywords = req.Keywords
	}
	if req.Confidence > 0 {
		if err := pkg.ValidateConfidence(req.Confidence); err != nil {
			s.logger.Debug("Confidence validation failed", "error", err)
			return nil, fmt.Errorf("confidence validation failed: %w", err)
		}
		analysis.Confidence = req.Confidence
	}

	err = s.dao.UpdateAnalysis(analysis)
	if err != nil {
		s.logger.Error("Failed to update knowledge entry", "error", err, "analysis_id", id)
		return nil, fmt.Errorf("failed to update knowledge entry: %w", err)
	}

	entry := &api.KnowledgeBaseEntry{
		ID:         analysis.ID,
		UserID:     analysis.UserID,
		Text:       analysis.Text,
		Title:      analysis.Title,
		Summary:    analysis.Summary,
		Topics:     analysis.Topics,
		Sentiment:  analysis.Sentiment,
		Keywords:   analysis.Keywords,
		Confidence: analysis.Confidence,
		CreatedAt:  analysis.CreatedAt.Format(time.RFC3339),
		UpdatedAt:  analysis.UpdatedAt.Format(time.RFC3339),
	}

	s.logger.Info("Knowledge entry updated successfully", "analysis_id", id, "user_id", userID)
	return entry, nil
}

func (s *Service) DeleteKnowledgeEntry(id uuid.UUID, userID uuid.UUID) error {
	s.logger.Debug("Starting knowledge entry deletion", "analysis_id", id, "user_id", userID)

	analysis, err := s.dao.GetAnalysisByID(id)
	if err != nil {
		s.logger.Error("Failed to get analysis for deletion", "error", err, "analysis_id", id)
		return fmt.Errorf("failed to get analysis: %w", err)
	}

	if analysis == nil {
		s.logger.Debug("Analysis not found", "analysis_id", id)
		return fmt.Errorf("analysis not found")
	}

	// Check if user has access to this analysis
	if analysis.UserID != userID {
		s.logger.Debug("Access denied to analysis", "analysis_id", id, "user_id", userID)
		return fmt.Errorf("access denied")
	}

	err = s.dao.DeleteAnalysis(id)
	if err != nil {
		s.logger.Error("Failed to delete knowledge entry", "error", err, "analysis_id", id)
		return fmt.Errorf("failed to delete knowledge entry: %w", err)
	}

	s.logger.Info("Knowledge entry deleted successfully", "analysis_id", id, "user_id", userID)
	return nil
}

func (s *Service) SearchKnowledge(req *api.SearchRequest, userID uuid.UUID) (*api.SearchResponse, error) {
	s.logger.Debug("Starting knowledge search", "user_id", userID, "topic", req.Topic, "keyword", req.Keyword, "sentiment", req.Sentiment)

	analyses, totalCount, err := s.dao.SearchAnalyses(req.Topic, req.Keyword, req.Sentiment, req.Page, req.Limit)
	if err != nil {
		s.logger.Error("Failed to search analyses", "error", err, "user_id", userID)
		return nil, fmt.Errorf("failed to search analyses: %w", err)
	}

	results := make([]api.KnowledgeBaseEntry, 0, len(analyses))
	for _, analysis := range analyses {
		// Only include analyses that belong to the user
		if analysis.UserID == userID {
			results = append(results, api.KnowledgeBaseEntry{
				ID:         analysis.ID,
				UserID:     analysis.UserID,
				Text:       analysis.Text,
				Title:      analysis.Title,
				Summary:    analysis.Summary,
				Topics:     analysis.Topics,
				Sentiment:  analysis.Sentiment,
				Keywords:   analysis.Keywords,
				Confidence: analysis.Confidence,
				CreatedAt:  analysis.CreatedAt.Format(time.RFC3339),
				UpdatedAt:  analysis.UpdatedAt.Format(time.RFC3339),
			})
		}
	}

	var totalPages int
	if req.Limit <= 0 {
		totalPages = 1
	} else {
		totalPages = int(math.Ceil(float64(totalCount) / float64(req.Limit)))
		if totalPages == 0 {
			totalPages = 1
		}
	}

	return &api.SearchResponse{
		Results:     results,
		CurrentPage: req.Page,
		TotalPages:  totalPages,
		TotalCount:  totalCount,
	}, nil
}


func (s *Service) generateJWT(userID string) string {
	now := time.Now()

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": userID,
		"iat": now.Unix(),
		"exp": now.Add(time.Duration(s.config.TokenExpiry) * time.Hour).Unix(),
		"iss": "joustlm",
		"aud": "joustlm-api",
	})

	tokenString, err := token.SignedString([]byte(s.config.JWTSecret))
	if err != nil {
		s.logger.Error("Failed to sign JWT token", "error", err, "user_id", userID)
		return ""
	}

	return tokenString
}

func (s *Service) generateRefreshToken() string {

	bytes := make([]byte, 32)
	rand.Read(bytes)
	timestamp := time.Now().Unix()
	tokenData := fmt.Sprintf("%d:%s", timestamp, hex.EncodeToString(bytes))
	return base64.URLEncoding.EncodeToString([]byte(tokenData))
}


func (s *Service) generateSecureRandomString(length int) string {
	return s.generateRandomString(length)
}

func (s *Service) generateRandomString(length int) string {
	const charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"

	bytes := make([]byte, length)
	rand.Read(bytes)
	result := make([]byte, length)

	for i, b := range bytes {
		result[i] = charset[b%byte(len(charset))]
	}

	return string(result)
}

func (s *Service) hashPassword(password string) string {

	salt := s.config.PasswordSalt
	saltedPassword := password + salt

	hash := sha256.Sum256([]byte(saltedPassword))
	return hex.EncodeToString(hash[:])
}

func (s *Service) validateJWT(tokenString string) (uuid.UUID, error) {
	s.logger.Debug("Starting JWT validation", "token_length", len(tokenString))

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(s.config.JWTSecret), nil
	})

	if err != nil {
		s.logger.Debug("JWT parsing failed", "error", err)
		return uuid.Nil, fmt.Errorf("invalid JWT token: %w", err)
	}

	if !token.Valid {
		s.logger.Debug("JWT token is not valid")
		return uuid.Nil, fmt.Errorf("invalid JWT token")
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		s.logger.Debug("Failed to extract claims from JWT")
		return uuid.Nil, fmt.Errorf("invalid JWT claims")
	}

	userID, ok := claims["sub"].(string)
	if !ok {
		s.logger.Debug("No valid sub claim found in JWT")
		return uuid.Nil, fmt.Errorf("invalid JWT subject")
	}

	s.logger.Debug("JWT validation successful", "user_id", userID)
	return uuid.MustParse(userID), nil
}
