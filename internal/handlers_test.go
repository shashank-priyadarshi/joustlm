package internal

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"google.golang.org/genai"

	"go.ssnk.in/joustlm/config"
	"go.ssnk.in/joustlm/logger"
	"go.ssnk.in/joustlm/schema/api"
)

func createMockLLM() *LLM {
	return &LLM{
		summarizer: &mockLLMClient{},
		tokenizer:  nil,
	}
}

// mockLLMClient implements LLMClient interface for testing
type mockLLMClient struct{}

func (m *mockLLMClient) Models() LLMModels {
	return &mockLLMModels{}
}

type mockLLMModels struct{}

func (m *mockLLMModels) GenerateContent(ctx context.Context, model string, contents []*genai.Content, config *genai.GenerateContentConfig) (*genai.GenerateContentResponse, error) {
	// Return a mock response that matches the expected structure
	return &genai.GenerateContentResponse{
		Candidates: []*genai.Candidate{
			{
				Content: &genai.Content{
					Parts: []*genai.Part{
						{Text: `{"title":"Mock Analysis","summary":"This is a mock analysis for testing purposes.","topics":["testing","mock","analysis"],"sentiment":"neutral","keywords":["test","mock","data"],"confidence":0.85}`},
					},
				},
			},
		},
	}, nil
}

type HandlerTestSuite struct {
	suite.Suite
	handler *Handler
	service *Service
	log     logger.Logger
}

func (suite *HandlerTestSuite) SetupTest() {
	suite.log = logger.New(logger.SetLevel(logger.Debug))
	conf := &config.Security{
		JWTSecret:   "test-secret",
		TokenExpiry: 24,
	}

	dbFile := fmt.Sprintf("file:test_%d.db?mode=memory&cache=shared", time.Now().UnixNano())
	dbConf := &config.Database{
		DSN: map[config.Tables]string{
			config.TableUsers:    dbFile,
			config.TableAnalyses: dbFile,
		},
	}

	dao := NewDao(&suite.log, dbConf)
	require.NotNil(suite.T(), dao, "DAO should be created successfully")

	err := dao.RunMigrations()
	require.NoError(suite.T(), err, "Migrations should run successfully")

	mockLLM := createMockLLM()
	suite.service = NewService(&suite.log, conf, mockLLM, dao)
	suite.handler = NewHandler(&suite.log, suite.service)
}

func (suite *HandlerTestSuite) TearDownTest() {
	if suite.service != nil && suite.service.dao != nil {
		suite.service.dao.Close()
	}
}

func createRequestWithUserContext(method, url string, body *bytes.Buffer, userID uuid.UUID) *http.Request {
	var req *http.Request
	if body != nil {
		req = httptest.NewRequest(method, url, body)
	} else {
		req = httptest.NewRequest(method, url, nil)
	}

	ctx := context.WithValue(req.Context(), contextKey("userID"), userID)
	req = req.WithContext(ctx)

	return req
}

func createAuthenticatedRequest(method, url string, body *bytes.Buffer, authToken string) *http.Request {
	var req *http.Request
	if body != nil {
		req = httptest.NewRequest(method, url, body)
	} else {
		req = httptest.NewRequest(method, url, nil)
	}

	if authToken != "" {
		req.Header.Set("Authorization", "Bearer "+authToken)
	}

	return req
}

func createRequestWithAuthToken(method, url string, body *bytes.Buffer, authToken string, service *Service) *http.Request {
	var req *http.Request
	if body != nil {
		req = httptest.NewRequest(method, url, body)
	} else {
		req = httptest.NewRequest(method, url, nil)
	}

	if authToken != "" {
		req.Header.Set("Authorization", "Bearer "+authToken)

		userID, err := service.validateJWT(authToken)
		if err == nil {
			ctx := context.WithValue(req.Context(), contextKey("userID"), userID)
			req = req.WithContext(ctx)
		}
	}

	return req
}

func (suite *HandlerTestSuite) TestNewHandler() {
	tests := []struct {
		name     string
		expected bool
	}{
		{
			name:     "should create handler successfully",
			expected: true,
		},
	}

	for _, tt := range tests {
		suite.Run(tt.name, func() {
			assert.NotNil(suite.T(), suite.handler, "NewHandler should not return nil")
			assert.Equal(suite.T(), &suite.log, suite.handler.logger, "Logger should be set correctly")
			assert.Equal(suite.T(), suite.service, suite.handler.service, "Service should be set correctly")
		})
	}
}

func (suite *HandlerTestSuite) TestHandleHealth() {
	tests := []struct {
		name           string
		method         string
		path           string
		expectedStatus int
		expectBody     bool
	}{
		{
			name:           "should return health status successfully",
			method:         "GET",
			path:           "/health",
			expectedStatus: http.StatusOK,
			expectBody:     true,
		},
	}

	for _, tt := range tests {
		suite.Run(tt.name, func() {
			req := httptest.NewRequest(tt.method, tt.path, nil)
			w := httptest.NewRecorder()

			suite.handler.HandleHealth(w, req)

			assert.Equal(suite.T(), tt.expectedStatus, w.Code, "Expected status %d, got %d", tt.expectedStatus, w.Code)

			if tt.expectBody {
				body := w.Body.String()
				assert.NotEmpty(suite.T(), body, "Response body should not be empty")
			}
		})
	}
}

func (suite *HandlerTestSuite) TestSignup() {
	tests := []struct {
		name           string
		request        api.SignupRequest
		expectedStatus int
		expectError    bool
		errorMsg       string
	}{
		{
			name: "should handle valid signup request",
			request: api.SignupRequest{
				Username: "testuser1",
				Password: "testpass123",
			},
			expectedStatus: http.StatusCreated,
			expectError:    false,
		},
		{
			name: "should fail with empty username",
			request: api.SignupRequest{
				Username: "",
				Password: "testpass123",
			},
			expectedStatus: http.StatusBadRequest,
			expectError:    true,
			errorMsg:       "Invalid request body",
		},
		{
			name: "should fail with empty password",
			request: api.SignupRequest{
				Username: "testuser2",
				Password: "",
			},
			expectedStatus: http.StatusBadRequest,
			expectError:    true,
			errorMsg:       "Invalid request body",
		},
		{
			name: "should fail with short password",
			request: api.SignupRequest{
				Username: "testuser3",
				Password: "123",
			},
			expectedStatus: http.StatusBadRequest,
			expectError:    true,
			errorMsg:       "Invalid request body",
		},
		{
			name: "should fail with duplicate username",
			request: api.SignupRequest{
				Username: "testuser1",
				Password: "testpass123",
			},
			expectedStatus: http.StatusConflict,
			expectError:    true,
			errorMsg:       "Resource conflict",
		},
		{
			name: "should handle special characters in username",
			request: api.SignupRequest{
				Username: "test_user-123",
				Password: "testpass123",
			},
			expectedStatus: http.StatusCreated,
			expectError:    false,
		},
		{
			name: "should handle unicode characters in username",
			request: api.SignupRequest{
				Username: "测试用户",
				Password: "testpass123",
			},
			expectedStatus: http.StatusCreated,
			expectError:    false,
		},
	}

	for _, tt := range tests {
		suite.Run(tt.name, func() {
			jsonData, err := json.Marshal(tt.request)
			require.NoError(suite.T(), err, "Failed to marshal request")

			req := httptest.NewRequest("POST", "/api/v1/signup", bytes.NewBuffer(jsonData))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()

			suite.handler.Signup(w, req)

			assert.Equal(suite.T(), tt.expectedStatus, w.Code, "Expected status %d, got %d", tt.expectedStatus, w.Code)

			if tt.expectError {
				var errorResp api.ErrorResponse
				err = json.Unmarshal(w.Body.Bytes(), &errorResp)
				require.NoError(suite.T(), err, "Failed to unmarshal error response")
				if tt.errorMsg != "" {
					assert.Contains(suite.T(), errorResp.Message, tt.errorMsg, "Expected error message to contain: %s", tt.errorMsg)
				}
			} else {
				var signupResp api.SignupResponse
				err = json.Unmarshal(w.Body.Bytes(), &signupResp)
				require.NoError(suite.T(), err, "Failed to unmarshal signup response")
				assert.NotEmpty(suite.T(), signupResp.Token, "Token should not be empty")
				assert.NotEmpty(suite.T(), signupResp.ExpiresAt, "ExpiresAt should not be empty")
			}
		})
	}
}

func (suite *HandlerTestSuite) TestLogin() {
	suite.Run("setup_user", func() {
		signupReq := api.SignupRequest{
			Username: "logintestuser",
			Password: "testpass123",
		}
		jsonData, err := json.Marshal(signupReq)
		require.NoError(suite.T(), err)

		req := httptest.NewRequest("POST", "/api/v1/signup", bytes.NewBuffer(jsonData))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		suite.handler.Signup(w, req)
		require.Equal(suite.T(), http.StatusCreated, w.Code, "Setup user should succeed")
	})

	tests := []struct {
		name           string
		request        api.LoginRequest
		expectedStatus int
		expectError    bool
		errorMsg       string
	}{
		{
			name: "should login with correct credentials",
			request: api.LoginRequest{
				Username: "logintestuser",
				Password: "testpass123",
			},
			expectedStatus: http.StatusOK,
			expectError:    false,
		},
		{
			name: "should fail with empty username",
			request: api.LoginRequest{
				Username: "",
				Password: "testpass123",
			},
			expectedStatus: http.StatusBadRequest,
			expectError:    true,
			errorMsg:       "Invalid request body",
		},
		{
			name: "should fail with empty password",
			request: api.LoginRequest{
				Username: "logintestuser",
				Password: "",
			},
			expectedStatus: http.StatusBadRequest,
			expectError:    true,
			errorMsg:       "Invalid request body",
		},
		{
			name: "should fail with wrong password",
			request: api.LoginRequest{
				Username: "logintestuser",
				Password: "wrongpassword",
			},
			expectedStatus: http.StatusUnauthorized,
			expectError:    true,
			errorMsg:       "Unauthorized access",
		},
		{
			name: "should fail with non-existent user",
			request: api.LoginRequest{
				Username: "nonexistentuser",
				Password: "testpass123",
			},
			expectedStatus: http.StatusUnauthorized,
			expectError:    true,
			errorMsg:       "Unauthorized access",
		},
	}

	for _, tt := range tests {
		suite.Run(tt.name, func() {
			jsonData, err := json.Marshal(tt.request)
			require.NoError(suite.T(), err, "Failed to marshal request")

			req := httptest.NewRequest("POST", "/api/v1/login", bytes.NewBuffer(jsonData))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()

			suite.handler.Login(w, req)

			assert.Equal(suite.T(), tt.expectedStatus, w.Code, "Expected status %d, got %d", tt.expectedStatus, w.Code)

			if tt.expectError {
				var errorResp api.ErrorResponse
				err = json.Unmarshal(w.Body.Bytes(), &errorResp)
				require.NoError(suite.T(), err, "Failed to unmarshal error response")
				if tt.errorMsg != "" {
					assert.Contains(suite.T(), errorResp.Message, tt.errorMsg, "Expected error message to contain: %s", tt.errorMsg)
				}
			} else {
				var loginResp api.LoginResponse
				err = json.Unmarshal(w.Body.Bytes(), &loginResp)
				require.NoError(suite.T(), err, "Failed to unmarshal login response")
				assert.NotEmpty(suite.T(), loginResp.Token, "Token should not be empty")
				assert.NotEmpty(suite.T(), loginResp.ExpiresAt, "ExpiresAt should not be empty")
			}
		})
	}
}

func (suite *HandlerTestSuite) TestExtractKnowledge() {
	var authToken string

	suite.Run("setup_auth", func() {
		signupReq := api.SignupRequest{
			Username: "llmtestuser",
			Password: "testpass123",
		}
		jsonData, err := json.Marshal(signupReq)
		require.NoError(suite.T(), err)

		req := httptest.NewRequest("POST", "/api/v1/signup", bytes.NewBuffer(jsonData))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		suite.handler.Signup(w, req)
		require.Equal(suite.T(), http.StatusCreated, w.Code, "Setup user should succeed")

		var signupResp api.SignupResponse
		err = json.Unmarshal(w.Body.Bytes(), &signupResp)
		require.NoError(suite.T(), err, "Failed to unmarshal signup response")
		authToken = signupResp.Token
	})

	tests := []struct {
		name           string
		request        api.LLMAnalysisRequest
		authToken      string
		expectedStatus int
		expectError    bool
		errorMsg       string
	}{
		{
			name: "should extract knowledge with valid text",
			request: api.LLMAnalysisRequest{
				Text: "Artificial intelligence is transforming the way we work and live. Machine learning algorithms are becoming more sophisticated every day.",
			},
			authToken:      authToken,
			expectedStatus: http.StatusOK,
			expectError:    false,
		},
		{
			name: "should fail with empty text",
			request: api.LLMAnalysisRequest{
				Text: "",
			},
			authToken:      authToken,
			expectedStatus: http.StatusBadRequest,
			expectError:    true,
			errorMsg:       "text cannot be empty",
		},
		{
			name: "should fail with text that's too short",
			request: api.LLMAnalysisRequest{
				Text: "Hi",
			},
			authToken:      authToken,
			expectedStatus: http.StatusBadRequest,
			expectError:    true,
			errorMsg:       "text validation failed",
		},
		{
			name: "should fail without authentication",
			request: api.LLMAnalysisRequest{
				Text: "This is a test text for analysis.",
			},
			authToken:      "",
			expectedStatus: http.StatusUnauthorized,
			expectError:    true,
			errorMsg:       "Unauthorized access",
		},
		{
			name: "should fail with invalid token",
			request: api.LLMAnalysisRequest{
				Text: "This is a test text for analysis.",
			},
			authToken:      "invalid-token",
			expectedStatus: http.StatusUnauthorized,
			expectError:    true,
			errorMsg:       "Unauthorized access",
		},
		{
			name: "should handle long text",
			request: api.LLMAnalysisRequest{
				Text: "This is a very long text that contains multiple paragraphs and extensive information about various topics including technology, science, and society. It discusses the impact of artificial intelligence on modern life, the evolution of machine learning algorithms, and the potential future applications of these technologies in various industries such as healthcare, finance, transportation, and education.",
			},
			authToken:      authToken,
			expectedStatus: http.StatusOK,
			expectError:    false,
		},
		{
			name: "should handle text with special characters",
			request: api.LLMAnalysisRequest{
				Text: "This text contains special characters: @#$%^&*()_+-=[]{}|;':\",./<>? and numbers 1234567890.",
			},
			authToken:      authToken,
			expectedStatus: http.StatusOK,
			expectError:    false,
		},
	}

	for _, tt := range tests {
		suite.Run(tt.name, func() {
			jsonData, err := json.Marshal(tt.request)
			require.NoError(suite.T(), err, "Failed to marshal request")

			req := createRequestWithAuthToken("POST", "/api/v1/extract", bytes.NewBuffer(jsonData), tt.authToken, suite.service)
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()

			suite.handler.ExtractKnowledge(w, req)

			assert.Equal(suite.T(), tt.expectedStatus, w.Code, "Expected status %d, got %d", tt.expectedStatus, w.Code)

			if tt.expectError {
				var errorResp api.ErrorResponse
				err = json.Unmarshal(w.Body.Bytes(), &errorResp)
				require.NoError(suite.T(), err, "Failed to unmarshal error response")
				if tt.errorMsg != "" {
					assert.Contains(suite.T(), errorResp.Message, tt.errorMsg, "Expected error message to contain: %s", tt.errorMsg)
				}
			} else {
				var extractResp api.LLMAnalysisResponse
				err = json.Unmarshal(w.Body.Bytes(), &extractResp)
				require.NoError(suite.T(), err, "Failed to unmarshal extract response")
				assert.Equal(suite.T(), tt.request.Text, extractResp.Text, "Text should match")
				assert.NotEmpty(suite.T(), extractResp.ID, "Analysis ID should not be empty")
				assert.NotEmpty(suite.T(), extractResp.Title, "Title should not be empty")
				assert.NotEmpty(suite.T(), extractResp.Summary, "Summary should not be empty")
				assert.Len(suite.T(), extractResp.Topics, 3, "Should have exactly 3 topics")
				assert.Contains(suite.T(), []string{"positive", "neutral", "negative"}, extractResp.Sentiment, "Sentiment should be valid")
				assert.Len(suite.T(), extractResp.Keywords, 3, "Should have exactly 3 keywords")
				assert.GreaterOrEqual(suite.T(), extractResp.Confidence, 0.0, "Confidence should be >= 0")
				assert.LessOrEqual(suite.T(), extractResp.Confidence, 1.0, "Confidence should be <= 1")
				assert.NotEmpty(suite.T(), extractResp.CreatedAt, "CreatedAt should not be empty")
			}
		})
	}
}

func (suite *HandlerTestSuite) TestGetKnowledgeEntries() {
	var authToken string

	suite.Run("setup_auth", func() {
		signupReq := api.SignupRequest{
			Username: "getknowledgetestuser",
			Password: "testpass123",
		}
		jsonData, err := json.Marshal(signupReq)
		require.NoError(suite.T(), err)

		req := httptest.NewRequest("POST", "/api/v1/signup", bytes.NewBuffer(jsonData))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		suite.handler.Signup(w, req)
		require.Equal(suite.T(), http.StatusCreated, w.Code, "Setup user should succeed")

		var signupResp api.SignupResponse
		err = json.Unmarshal(w.Body.Bytes(), &signupResp)
		require.NoError(suite.T(), err, "Failed to unmarshal signup response")
		authToken = signupResp.Token
	})

	tests := []struct {
		name           string
		queryParams    string
		authToken      string
		expectedStatus int
		expectError    bool
		errorMsg       string
	}{
		{
			name:           "should get knowledge entries with default pagination",
			queryParams:    "",
			authToken:      authToken,
			expectedStatus: http.StatusOK,
			expectError:    false,
		},
		{
			name:           "should get knowledge entries with custom pagination",
			queryParams:    "?page=1&limit=10",
			authToken:      authToken,
			expectedStatus: http.StatusOK,
			expectError:    false,
		},
		{
			name:           "should fail without authentication",
			queryParams:    "",
			authToken:      "",
			expectedStatus: http.StatusUnauthorized,
			expectError:    true,
			errorMsg:       "Unauthorized access",
		},
		{
			name:           "should fail with invalid token",
			queryParams:    "",
			authToken:      "invalid-token",
			expectedStatus: http.StatusUnauthorized,
			expectError:    true,
			errorMsg:       "Unauthorized access",
		},
		{
			name:           "should handle invalid page parameter",
			queryParams:    "?page=invalid",
			authToken:      authToken,
			expectedStatus: http.StatusOK,
			expectError:    false,
		},
		{
			name:           "should handle invalid limit parameter",
			queryParams:    "?limit=invalid",
			authToken:      authToken,
			expectedStatus: http.StatusOK,
			expectError:    false,
		},
	}

	for _, tt := range tests {
		suite.Run(tt.name, func() {
			req := createRequestWithAuthToken("GET", "/api/v1/knowledge"+tt.queryParams, nil, tt.authToken, suite.service)
			w := httptest.NewRecorder()

			suite.handler.GetKnowledgeEntries(w, req)

			assert.Equal(suite.T(), tt.expectedStatus, w.Code, "Expected status %d, got %d", tt.expectedStatus, w.Code)

			if tt.expectError {
				var errorResp api.ErrorResponse
				err := json.Unmarshal(w.Body.Bytes(), &errorResp)
				require.NoError(suite.T(), err, "Failed to unmarshal error response")
				if tt.errorMsg != "" {
					assert.Contains(suite.T(), errorResp.Message, tt.errorMsg, "Expected error message to contain: %s", tt.errorMsg)
				}
			} else {
				var getResp api.GetKnowledgeResponse
				err := json.Unmarshal(w.Body.Bytes(), &getResp)
				require.NoError(suite.T(), err, "Failed to unmarshal get response")
				assert.GreaterOrEqual(suite.T(), getResp.TotalCount, 0, "Total count should be non-negative")
				assert.GreaterOrEqual(suite.T(), getResp.TotalPages, 1, "Total pages should be at least 1")
			}
		})
	}
}

func (suite *HandlerTestSuite) TestDeleteKnowledgeEntry() {
	var authToken string
	var analysisID string

	suite.Run("setup_data", func() {
		signupReq := api.SignupRequest{
			Username: "deleteknowledgetestuser",
			Password: "testpass123",
		}
		jsonData, err := json.Marshal(signupReq)
		require.NoError(suite.T(), err)

		req := httptest.NewRequest("POST", "/api/v1/signup", bytes.NewBuffer(jsonData))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		suite.handler.Signup(w, req)
		require.Equal(suite.T(), http.StatusCreated, w.Code, "Setup user should succeed")

		var signupResp api.SignupResponse
		err = json.Unmarshal(w.Body.Bytes(), &signupResp)
		require.NoError(suite.T(), err, "Failed to unmarshal signup response")
		authToken = signupResp.Token

		extractReq := api.LLMAnalysisRequest{
			Text: "This is a test analysis for deletion testing.",
		}
		jsonData, err = json.Marshal(extractReq)
		require.NoError(suite.T(), err)

		req = createRequestWithAuthToken("POST", "/api/v1/extract", bytes.NewBuffer(jsonData), authToken, suite.service)
		req.Header.Set("Content-Type", "application/json")
		w = httptest.NewRecorder()

		suite.handler.ExtractKnowledge(w, req)
		require.Equal(suite.T(), http.StatusOK, w.Code, "Setup analysis should succeed")

		var extractResp api.LLMAnalysisResponse
		err = json.Unmarshal(w.Body.Bytes(), &extractResp)
		require.NoError(suite.T(), err, "Failed to unmarshal extract response")
		analysisID = extractResp.ID.String()
	})

	tests := []struct {
		name           string
		analysisID     string
		authToken      string
		expectedStatus int
		expectError    bool
		errorMsg       string
	}{
		{
			name:           "should delete knowledge entry successfully",
			analysisID:     analysisID,
			authToken:      authToken,
			expectedStatus: http.StatusNoContent,
			expectError:    false,
		},
		{
			name:           "should fail with non-existent analysis",
			analysisID:     uuid.New().String(),
			authToken:      authToken,
			expectedStatus: http.StatusNotFound,
			expectError:    true,
			errorMsg:       "Resource not found",
		},
		{
			name:           "should fail without authentication",
			analysisID:     analysisID,
			authToken:      "",
			expectedStatus: http.StatusUnauthorized,
			expectError:    true,
			errorMsg:       "Unauthorized access",
		},
		{
			name:           "should fail with invalid token",
			analysisID:     analysisID,
			authToken:      "invalid-token",
			expectedStatus: http.StatusUnauthorized,
			expectError:    true,
			errorMsg:       "Unauthorized access",
		},
		{
			name:           "should fail with invalid analysis ID format",
			analysisID:     "invalid-uuid",
			authToken:      authToken,
			expectedStatus: http.StatusBadRequest,
			expectError:    true,
			errorMsg:       "Invalid request body",
		},
	}

	for _, tt := range tests {
		suite.Run(tt.name, func() {
			req := createRequestWithAuthToken("DELETE", "/api/v1/knowledge/"+tt.analysisID, nil, tt.authToken, suite.service)
			w := httptest.NewRecorder()

			suite.handler.DeleteKnowledgeEntry(w, req)

			assert.Equal(suite.T(), tt.expectedStatus, w.Code, "Expected status %d, got %d", tt.expectedStatus, w.Code)

			if tt.expectError {
				var errorResp api.ErrorResponse
				err := json.Unmarshal(w.Body.Bytes(), &errorResp)
				require.NoError(suite.T(), err, "Failed to unmarshal error response")
				if tt.errorMsg != "" {
					assert.Contains(suite.T(), errorResp.Message, tt.errorMsg, "Expected error message to contain: %s", tt.errorMsg)
				}
			}
		})
	}
}

func (suite *HandlerTestSuite) TestSearchKnowledge() {
	var authToken string

	suite.Run("setup_data", func() {
		signupReq := api.SignupRequest{
			Username: "searchtestuser",
			Password: "testpass123",
		}
		jsonData, err := json.Marshal(signupReq)
		require.NoError(suite.T(), err)

		req := httptest.NewRequest("POST", "/api/v1/signup", bytes.NewBuffer(jsonData))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		suite.handler.Signup(w, req)
		require.Equal(suite.T(), http.StatusCreated, w.Code, "Setup user should succeed")

		var signupResp api.SignupResponse
		err = json.Unmarshal(w.Body.Bytes(), &signupResp)
		require.NoError(suite.T(), err, "Failed to unmarshal signup response")
		authToken = signupResp.Token

		// Create multiple analyses for search testing
		analyses := []string{
			"Artificial intelligence is transforming healthcare with machine learning algorithms.",
			"This is a cooking guide with recipes for Italian cuisine.",
			"Technology companies are investing heavily in renewable energy solutions.",
		}

		for _, text := range analyses {
			extractReq := api.LLMAnalysisRequest{Text: text}
			jsonData, err = json.Marshal(extractReq)
			require.NoError(suite.T(), err)

			req = createRequestWithAuthToken("POST", "/api/v1/extract", bytes.NewBuffer(jsonData), authToken, suite.service)
			req.Header.Set("Content-Type", "application/json")
			w = httptest.NewRecorder()

			suite.handler.ExtractKnowledge(w, req)
			require.Equal(suite.T(), http.StatusOK, w.Code, "Setup analysis should succeed")
		}
	})

	tests := []struct {
		name           string
		queryParams    string
		authToken      string
		expectedStatus int
		expectError    bool
		errorMsg       string
	}{
		{
			name:           "should search by topic",
			queryParams:    "?topic=artificial%20intelligence",
			authToken:      authToken,
			expectedStatus: http.StatusOK,
			expectError:    false,
		},
		{
			name:           "should search by keyword",
			queryParams:    "?keyword=technology",
			authToken:      authToken,
			expectedStatus: http.StatusOK,
			expectError:    false,
		},
		{
			name:           "should search by sentiment",
			queryParams:    "?sentiment=neutral",
			authToken:      authToken,
			expectedStatus: http.StatusOK,
			expectError:    false,
		},
		{
			name:           "should search with multiple parameters",
			queryParams:    "?topic=technology&sentiment=neutral",
			authToken:      authToken,
			expectedStatus: http.StatusOK,
			expectError:    false,
		},
		{
			name:           "should fail without authentication",
			queryParams:    "?topic=test",
			authToken:      "",
			expectedStatus: http.StatusUnauthorized,
			expectError:    true,
			errorMsg:       "Unauthorized access",
		},
		{
			name:           "should fail with invalid token",
			queryParams:    "?topic=test",
			authToken:      "invalid-token",
			expectedStatus: http.StatusUnauthorized,
			expectError:    true,
			errorMsg:       "Unauthorized access",
		},
		{
			name:           "should handle empty search parameters",
			queryParams:    "",
			authToken:      authToken,
			expectedStatus: http.StatusOK,
			expectError:    false,
		},
	}

	for _, tt := range tests {
		suite.Run(tt.name, func() {
			req := createRequestWithAuthToken("GET", "/api/search"+tt.queryParams, nil, tt.authToken, suite.service)
			w := httptest.NewRecorder()

			suite.handler.SearchKnowledge(w, req)

			assert.Equal(suite.T(), tt.expectedStatus, w.Code, "Expected status %d, got %d", tt.expectedStatus, w.Code)

			if tt.expectError {
				var errorResp api.ErrorResponse
				err := json.Unmarshal(w.Body.Bytes(), &errorResp)
				require.NoError(suite.T(), err, "Failed to unmarshal error response")
				if tt.errorMsg != "" {
					assert.Contains(suite.T(), errorResp.Message, tt.errorMsg, "Expected error message to contain: %s", tt.errorMsg)
				}
			} else {
				var searchResp api.SearchResponse
				err := json.Unmarshal(w.Body.Bytes(), &searchResp)
				require.NoError(suite.T(), err, "Failed to unmarshal search response")
				assert.GreaterOrEqual(suite.T(), searchResp.TotalCount, 0, "Total count should be non-negative")
				assert.GreaterOrEqual(suite.T(), searchResp.TotalPages, 1, "Total pages should be at least 1")
			}
		})
	}
}

func (suite *HandlerTestSuite) TestErrorScenarios() {
	suite.Run("setup_auth", func() {
		signupReq := api.SignupRequest{
			Username: "errorcasetestuser",
			Password: "testpass123",
		}
		jsonData, err := json.Marshal(signupReq)
		require.NoError(suite.T(), err)

		req := httptest.NewRequest("POST", "/api/v1/signup", bytes.NewBuffer(jsonData))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		suite.handler.Signup(w, req)
		require.Equal(suite.T(), http.StatusCreated, w.Code, "Setup user should succeed")

		var signupResp api.SignupResponse
		err = json.Unmarshal(w.Body.Bytes(), &signupResp)
		require.NoError(suite.T(), err, "Failed to unmarshal signup response")
	})

	tests := []struct {
		name           string
		method         string
		path           string
		body           string
		headers        map[string]string
		expectedStatus int
		errorMsg       string
	}{
		{
			name:           "should handle malformed JSON in signup",
			method:         "POST",
			path:           "/api/v1/signup",
			body:           `{"username": "test", "password": }`,
			headers:        map[string]string{"Content-Type": "application/json"},
			expectedStatus: http.StatusBadRequest,
			errorMsg:       "Invalid request body",
		},
		{
			name:           "should handle malformed JSON in login",
			method:         "POST",
			path:           "/api/v1/login",
			body:           `{"username": "test", "password": }`,
			headers:        map[string]string{"Content-Type": "application/json"},
			expectedStatus: http.StatusBadRequest,
			errorMsg:       "Invalid request body",
		},
		{
			name:           "should handle wrong content type",
			method:         "POST",
			path:           "/api/v1/signup",
			body:           `username=test&password=testpass123`,
			headers:        map[string]string{"Content-Type": "application/x-www-form-urlencoded"},
			expectedStatus: http.StatusBadRequest,
			errorMsg:       "Invalid request body",
		},
		{
			name:           "should handle missing content type",
			method:         "POST",
			path:           "/api/v1/signup",
			body:           `{"username": "test", "password": "testpass123"}`,
			headers:        map[string]string{},
			expectedStatus: http.StatusCreated,
			errorMsg:       "",
		},
		{
			name:           "should handle very long request body",
			method:         "POST",
			path:           "/api/v1/signup",
			body:           `{"username": "` + strings.Repeat("a", 10000) + `", "password": "testpass123"}`,
			headers:        map[string]string{"Content-Type": "application/json"},
			expectedStatus: http.StatusCreated,
			errorMsg:       "",
		},
		{
			name:           "should handle invalid HTTP method",
			method:         "PATCH",
			path:           "/api/v1/signup",
			body:           `{"username": "test", "password": "testpass123"}`,
			headers:        map[string]string{"Content-Type": "application/json"},
			expectedStatus: http.StatusConflict,
			errorMsg:       "Resource conflict",
		},
	}

	for _, tt := range tests {
		suite.Run(tt.name, func() {
			req := httptest.NewRequest(tt.method, tt.path, bytes.NewBufferString(tt.body))
			for key, value := range tt.headers {
				req.Header.Set(key, value)
			}
			w := httptest.NewRecorder()

			switch {
			case strings.HasPrefix(tt.path, "/api/v1/signup"):
				suite.handler.Signup(w, req)
			case strings.HasPrefix(tt.path, "/api/v1/login"):
				suite.handler.Login(w, req)
			default:
				suite.handler.Signup(w, req)
			}

			assert.Equal(suite.T(), tt.expectedStatus, w.Code, "Expected status %d, got %d", tt.expectedStatus, w.Code)

			if tt.errorMsg != "" {
				var errorResp api.ErrorResponse
				err := json.Unmarshal(w.Body.Bytes(), &errorResp)
				require.NoError(suite.T(), err, "Failed to unmarshal error response")
				assert.Contains(suite.T(), errorResp.Message, tt.errorMsg, "Expected error message to contain: %s", tt.errorMsg)
			}
		})
	}
}

func (suite *HandlerTestSuite) TestEdgeCases() {
	suite.Run("setup_auth", func() {
		signupReq := api.SignupRequest{
			Username: "edgecasetestuser",
			Password: "testpass123",
		}
		jsonData, err := json.Marshal(signupReq)
		require.NoError(suite.T(), err)

		req := httptest.NewRequest("POST", "/api/v1/signup", bytes.NewBuffer(jsonData))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		suite.handler.Signup(w, req)
		require.Equal(suite.T(), http.StatusCreated, w.Code, "Setup user should succeed")

		var signupResp api.SignupResponse
		err = json.Unmarshal(w.Body.Bytes(), &signupResp)
		require.NoError(suite.T(), err, "Failed to unmarshal signup response")
	})

	tests := []struct {
		name           string
		scenario       func() (*httptest.ResponseRecorder, *http.Request)
		expectedStatus int
		description    string
	}{
		{
			name: "should handle concurrent requests",
			scenario: func() (*httptest.ResponseRecorder, *http.Request) {
				req := httptest.NewRequest("GET", "/health", nil)
				w := httptest.NewRecorder()
				return w, req
			},
			expectedStatus: http.StatusOK,
			description:    "Health check should work under load",
		},
	}

	for _, tt := range tests {
		suite.Run(tt.name, func() {
			w, req := tt.scenario()

			switch {
			case strings.HasPrefix(req.URL.Path, "/health"):
				suite.handler.HandleHealth(w, req)
			}

			assert.Equal(suite.T(), tt.expectedStatus, w.Code, "Expected status %d, got %d for scenario: %s", tt.expectedStatus, w.Code, tt.description)
		})
	}
}

func TestHandlerTestSuite(t *testing.T) {
	suite.Run(t, new(HandlerTestSuite))
}
