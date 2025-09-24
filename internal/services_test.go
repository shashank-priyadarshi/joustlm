package internal

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"go.ssnk.in/joustlm/config"
	"go.ssnk.in/joustlm/logger"
	"go.ssnk.in/joustlm/schema/api"
)

type ServiceTestSuite struct {
	suite.Suite
	dao *Dao
	log logger.Logger
}

func (suite *ServiceTestSuite) SetupTest() {
	suite.log = logger.New(logger.SetLevel(logger.Debug))

	dbFile := fmt.Sprintf("file:test_%d.db?mode=memory&cache=shared", time.Now().UnixNano())
	dbConf := &config.Database{
		DSN: map[config.Tables]string{
			config.TableUsers:    dbFile,
			config.TableAnalyses: dbFile,
		},
	}

	suite.dao = NewDao(&suite.log, dbConf)
	require.NotNil(suite.T(), suite.dao, "DAO should be created successfully")

	err := suite.dao.RunMigrations()
	require.NoError(suite.T(), err, "Migrations should run successfully")
}

func (suite *ServiceTestSuite) TearDownTest() {
	if suite.dao != nil {
		suite.dao.Close()
	}
}

func (suite *ServiceTestSuite) TestNewService() {
	tests := []struct {
		name     string
		expected bool
	}{
		{
			name:     "should create service successfully",
			expected: true,
		},
	}

	for _, tt := range tests {
		suite.Run(tt.name, func() {
			conf := &config.Security{}
			mockLLM := createMockLLM()
			service := NewService(&suite.log, conf, mockLLM, suite.dao)

			assert.NotNil(suite.T(), service, "NewService should not return nil")
			assert.Equal(suite.T(), &suite.log, service.logger, "Logger should be set correctly")
			assert.Equal(suite.T(), suite.dao, service.dao, "DAO should be set correctly")
			assert.Equal(suite.T(), conf, service.config, "Config should be set correctly")
		})
	}
}

func (suite *ServiceTestSuite) TestServiceHashPassword() {
	tests := []struct {
		name     string
		expected bool
	}{
		{
			name:     "should hash password correctly",
			expected: true,
		},
	}

	for _, tt := range tests {
		suite.Run(tt.name, func() {
			conf := &config.Security{
				PasswordSalt: "test-salt",
				JWTSecret:    "test-secret",
				TokenExpiry:  24,
			}
			mockLLM := createMockLLM()
			service := NewService(&suite.log, conf, mockLLM, suite.dao)

			password := "testpassword"
			hash1 := service.hashPassword(password)
			hash2 := service.hashPassword(password)

			assert.Equal(suite.T(), hash1, hash2, "Same password should produce same hash")
			assert.NotEqual(suite.T(), hash1, password, "Hash should not be the same as password")
			assert.NotEmpty(suite.T(), hash1, "Hash should not be empty")
		})
	}
}

func (suite *ServiceTestSuite) TestServiceSignupUser() {
	tests := []struct {
		name        string
		req         api.SignupRequest
		expectError bool
		errorMsg    string
	}{
		{
			name: "should signup user successfully with valid data",
			req: api.SignupRequest{
				Username: "testuser1",
				Password: "testpass123",
			},
			expectError: false,
		},
		{
			name: "should fail with duplicate username",
			req: api.SignupRequest{
				Username: "testuser1",
				Password: "testpass123",
			},
			expectError: true,
			errorMsg:    "username already exists",
		},
		{
			name: "should handle empty username (validation at handler level)",
			req: api.SignupRequest{
				Username: "",
				Password: "testpass123",
			},
			expectError: false,
		},
		{
			name: "should handle empty password (validation at handler level)",
			req: api.SignupRequest{
				Username: "testuser2",
				Password: "",
			},
			expectError: false,
		},
		{
			name: "should handle special characters in username",
			req: api.SignupRequest{
				Username: "test_user-123",
				Password: "testpass123",
			},
			expectError: false,
		},
		{
			name: "should handle unicode characters",
			req: api.SignupRequest{
				Username: "测试用户",
				Password: "testpass123",
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		suite.Run(tt.name, func() {
			conf := &config.Security{
				PasswordSalt: "test-salt",
				JWTSecret:    "test-secret",
				TokenExpiry:  24,
			}
			mockLLM := createMockLLM()
			service := NewService(&suite.log, conf, mockLLM, suite.dao)

			if tt.req.Username != "" && tt.req.Username != "testuser1" {
				tt.req.Username = fmt.Sprintf("%s_%d", tt.req.Username, time.Now().UnixNano())
			}

			response, err := service.SignupUser(context.Background(), &tt.req)

			if tt.expectError {
				assert.Error(suite.T(), err, "Expected error for test case: %s", tt.name)
				if tt.errorMsg != "" {
					assert.Contains(suite.T(), err.Error(), tt.errorMsg, "Expected error message to contain: %s", tt.errorMsg)
				}
				assert.Nil(suite.T(), response, "Response should be nil on error")
			} else {
				assert.NoError(suite.T(), err, "Expected no error for test case: %s", tt.name)
				assert.NotNil(suite.T(), response, "Response should not be nil on success")
				assert.NotEmpty(suite.T(), response.Token, "Token should not be empty")
				assert.NotEmpty(suite.T(), response.RefreshToken, "Refresh token should not be empty")
				assert.NotEmpty(suite.T(), response.ExpiresAt, "ExpiresAt should not be empty")
			}
		})
	}
}

func (suite *ServiceTestSuite) TestServiceLoginUser() {
	tests := []struct {
		name        string
		setupUser   bool
		req         api.LoginRequest
		expectError bool
		errorMsg    string
	}{
		{
			name:      "should fail with non-existent user",
			setupUser: false,
			req: api.LoginRequest{
				Username: "nonexistent",
				Password: "testpass123",
			},
			expectError: true,
			errorMsg:    "invalid credentials",
		},
		{
			name:      "should succeed with correct credentials",
			setupUser: true,
			req: api.LoginRequest{
				Username: "testuser",
				Password: "testpass123",
			},
			expectError: false,
		},
		{
			name:      "should fail with wrong password",
			setupUser: true,
			req: api.LoginRequest{
				Username: "testuser",
				Password: "wrongpassword",
			},
			expectError: true,
			errorMsg:    "invalid credentials",
		},
		{
			name:      "should fail with empty username",
			setupUser: false,
			req: api.LoginRequest{
				Username: "",
				Password: "testpass123",
			},
			expectError: true,
		},
		{
			name:      "should fail with empty password",
			setupUser: false,
			req: api.LoginRequest{
				Username: "testuser",
				Password: "",
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		suite.Run(tt.name, func() {
			conf := &config.Security{
				PasswordSalt: "test-salt",
				JWTSecret:    "test-secret",
				TokenExpiry:  24,
			}
			mockLLM := createMockLLM()
			service := NewService(&suite.log, conf, mockLLM, suite.dao)

			if tt.setupUser {
				uniqueUsername := fmt.Sprintf("testuser_%d", time.Now().UnixNano())
				signupReq := api.SignupRequest{
					Username: uniqueUsername,
					Password: "testpass123",
				}
				_, err := service.SignupUser(context.Background(), &signupReq)
				require.NoError(suite.T(), err, "Setup user should succeed")
				tt.req.Username = uniqueUsername
			}

			response, err := service.LoginUser(context.Background(), &tt.req)

			if tt.expectError {
				assert.Error(suite.T(), err, "Expected error for test case: %s", tt.name)
				if tt.errorMsg != "" {
					assert.Contains(suite.T(), err.Error(), tt.errorMsg, "Expected error message to contain: %s", tt.errorMsg)
				}
				assert.Nil(suite.T(), response, "Response should be nil on error")
			} else {
				assert.NoError(suite.T(), err, "Expected no error for test case: %s", tt.name)
				assert.NotNil(suite.T(), response, "Response should not be nil on success")
				assert.NotEmpty(suite.T(), response.Token, "Token should not be empty")
				assert.NotEmpty(suite.T(), response.RefreshToken, "Refresh token should not be empty")
				assert.NotEmpty(suite.T(), response.ExpiresAt, "ExpiresAt should not be empty")
			}
		})
	}
}

func (suite *ServiceTestSuite) TestServiceLogoutUser() {
	tests := []struct {
		name        string
		setupToken  bool
		token       string
		expectError bool
	}{
		{
			name:        "should logout with valid token",
			setupToken:  true,
			token:       "valid-token",
			expectError: false,
		},
		{
			name:        "should fail with invalid token",
			setupToken:  false,
			token:       "invalid-token",
			expectError: true,
		},
		{
			name:        "should fail with empty token",
			setupToken:  false,
			token:       "",
			expectError: true,
		},
	}

	for _, tt := range tests {
		suite.Run(tt.name, func() {
			conf := &config.Security{
				PasswordSalt: "test-salt",
				JWTSecret:    "test-secret",
				TokenExpiry:  24,
			}
			mockLLM := createMockLLM()
			service := NewService(&suite.log, conf, mockLLM, suite.dao)

			if tt.setupToken {
				uniqueUsername := fmt.Sprintf("testuser_%d", time.Now().UnixNano())
				signupReq := api.SignupRequest{
					Username: uniqueUsername,
					Password: "testpass123",
				}
				signupResp, err := service.SignupUser(context.Background(), &signupReq)
				require.NoError(suite.T(), err, "Setup user should succeed")
				tt.token = signupResp.Token
			}

			err := service.LogoutUser(context.Background(), tt.token)

			if tt.expectError {
				assert.Error(suite.T(), err, "Expected error for test case: %s", tt.name)
			} else {
				assert.NoError(suite.T(), err, "Expected no error for test case: %s", tt.name)
			}
		})
	}
}

func (suite *ServiceTestSuite) TestServiceValidateJWT() {
	tests := []struct {
		name        string
		setupToken  bool
		token       string
		expectError bool
		expectUser  bool
	}{
		{
			name:        "should validate with valid token",
			setupToken:  true,
			token:       "valid-token",
			expectError: false,
			expectUser:  true,
		},
		{
			name:        "should fail with invalid token",
			setupToken:  false,
			token:       "invalid-token",
			expectError: true,
			expectUser:  false,
		},
		{
			name:        "should fail with empty token",
			setupToken:  false,
			token:       "",
			expectError: true,
			expectUser:  false,
		},
		{
			name:        "should fail with malformed token",
			setupToken:  false,
			token:       "not.a.valid.jwt",
			expectError: true,
			expectUser:  false,
		},
	}

	for _, tt := range tests {
		suite.Run(tt.name, func() {
			conf := &config.Security{
				PasswordSalt: "test-salt",
				JWTSecret:    "test-secret",
				TokenExpiry:  24,
			}
			mockLLM := createMockLLM()
			service := NewService(&suite.log, conf, mockLLM, suite.dao)

			if tt.setupToken {
				uniqueUsername := fmt.Sprintf("testuser_%d", time.Now().UnixNano())
				signupReq := api.SignupRequest{
					Username: uniqueUsername,
					Password: "testpass123",
				}
				signupResp, err := service.SignupUser(context.Background(), &signupReq)
				require.NoError(suite.T(), err, "Setup user should succeed")
				tt.token = signupResp.Token
			}

			userID, err := service.validateJWT(tt.token)

			if tt.expectError {
				assert.Error(suite.T(), err, "Expected error for test case: %s", tt.name)
				assert.Equal(suite.T(), uuid.Nil, userID, "User ID should be nil on error")
			} else {
				assert.NoError(suite.T(), err, "Expected no error for test case: %s", tt.name)
				if tt.expectUser {
					assert.NotEqual(suite.T(), uuid.Nil, userID, "User ID should not be nil on success")
				}
			}
		})
	}
}

func (suite *ServiceTestSuite) TestServiceExtractKnowledge() {
	tests := []struct {
		name        string
		setupUser   bool
		req         api.LLMAnalysisRequest
		expectError bool
		errorMsg    string
	}{
		{
			name:      "should extract knowledge successfully",
			setupUser: true,
			req: api.LLMAnalysisRequest{
				Text: "Artificial intelligence is transforming the way we work and live. Machine learning algorithms are becoming more sophisticated every day, enabling new applications in healthcare, finance, and transportation.",
			},
			expectError: false,
		},
		{
			name:      "should handle short text",
			setupUser: true,
			req: api.LLMAnalysisRequest{
				Text: "This is a short text for analysis.",
			},
			expectError: false,
		},
		{
			name:      "should handle long text",
			setupUser: true,
			req: api.LLMAnalysisRequest{
				Text: "This is a very long text that contains multiple paragraphs and extensive information about various topics including technology, science, and society. It discusses the impact of artificial intelligence on modern life, the evolution of machine learning algorithms, and the potential future applications of these technologies in various industries such as healthcare, finance, transportation, and education. The text also explores the challenges and opportunities presented by these technological advances, including ethical considerations, privacy concerns, and the need for responsible development and deployment of AI systems.",
			},
			expectError: false,
		},
		{
			name:      "should handle text with special characters",
			setupUser: true,
			req: api.LLMAnalysisRequest{
				Text: "This text contains special characters: @#$%^&*()_+-=[]{}|;':\",./<>? and numbers 1234567890.",
			},
			expectError: false,
		},
		{
			name:      "should handle empty text",
			setupUser: true,
			req: api.LLMAnalysisRequest{
				Text: "",
			},
			expectError: true,
			errorMsg:    "text cannot be empty",
		},
		{
			name:      "should handle text that's too short",
			setupUser: true,
			req: api.LLMAnalysisRequest{
				Text: "Hi",
			},
			expectError: true,
			errorMsg:    "text validation failed",
		},
	}

	for _, tt := range tests {
		suite.Run(tt.name, func() {
			conf := &config.Security{
				PasswordSalt: "test-salt",
				JWTSecret:    "test-secret",
				TokenExpiry:  24,
			}
			mockLLM := createMockLLM()
			service := NewService(&suite.log, conf, mockLLM, suite.dao)

			var userID uuid.UUID
			if tt.setupUser {
				uniqueUsername := fmt.Sprintf("testuser_%d", time.Now().UnixNano())
				signupReq := api.SignupRequest{
					Username: uniqueUsername,
					Password: "testpass123",
				}
				signupResp, err := service.SignupUser(context.Background(), &signupReq)
				require.NoError(suite.T(), err, "Setup user should succeed")

				userIDFromToken, err := service.validateJWT(signupResp.Token)
				require.NoError(suite.T(), err, "Should validate JWT")
				userID = userIDFromToken
			} else {
				userID = uuid.New()
			}

			response, err := service.ExtractKnowledge(context.Background(), &tt.req, userID)

			if tt.expectError {
				assert.Error(suite.T(), err, "Expected error for test case: %s", tt.name)
				if tt.errorMsg != "" {
					assert.Contains(suite.T(), err.Error(), tt.errorMsg, "Expected error message to contain: %s", tt.errorMsg)
				}
				assert.Nil(suite.T(), response, "Response should be nil on error")
			} else {
				assert.NoError(suite.T(), err, "Expected no error for test case: %s", tt.name)
				assert.NotNil(suite.T(), response, "Response should not be nil on success")
				assert.Equal(suite.T(), tt.req.Text, response.Text, "Text should match")
				assert.NotEmpty(suite.T(), response.ID, "Analysis ID should not be empty")
				assert.NotEmpty(suite.T(), response.Title, "Title should not be empty")
				assert.NotEmpty(suite.T(), response.Summary, "Summary should not be empty")
				assert.Len(suite.T(), response.Topics, 3, "Should have exactly 3 topics")
				assert.Contains(suite.T(), []string{"positive", "neutral", "negative"}, response.Sentiment, "Sentiment should be valid")
				assert.Len(suite.T(), response.Keywords, 3, "Should have exactly 3 keywords")
				assert.GreaterOrEqual(suite.T(), response.Confidence, 0.0, "Confidence should be >= 0")
				assert.LessOrEqual(suite.T(), response.Confidence, 1.0, "Confidence should be <= 1")
				assert.NotEmpty(suite.T(), response.CreatedAt, "CreatedAt should not be empty")
			}
		})
	}
}

func (suite *ServiceTestSuite) TestServiceGetKnowledgeEntries() {
	tests := []struct {
		name        string
		setupData   bool
		userID      uuid.UUID
		page        int
		limit       int
		expectError bool
	}{
		{
			name:        "should get knowledge entries with pagination",
			setupData:   true,
			userID:      uuid.New(),
			page:        1,
			limit:       10,
			expectError: false,
		},
		{
			name:        "should handle empty results",
			setupData:   false,
			userID:      uuid.New(),
			page:        1,
			limit:       10,
			expectError: false,
		},
		{
			name:        "should handle large page numbers",
			setupData:   false,
			userID:      uuid.New(),
			page:        999,
			limit:       10,
			expectError: false,
		},
		{
			name:        "should handle zero limit",
			setupData:   false,
			userID:      uuid.New(),
			page:        1,
			limit:       0,
			expectError: false,
		},
		{
			name:        "should handle negative page",
			setupData:   false,
			userID:      uuid.New(),
			page:        -1,
			limit:       10,
			expectError: false,
		},
	}

	for _, tt := range tests {
		suite.Run(tt.name, func() {
			conf := &config.Security{
				PasswordSalt: "test-salt",
				JWTSecret:    "test-secret",
				TokenExpiry:  24,
			}
			mockLLM := createMockLLM()
			service := NewService(&suite.log, conf, mockLLM, suite.dao)

			if tt.setupData {
				uniqueUsername := fmt.Sprintf("testuser_%d", time.Now().UnixNano())
				signupReq := api.SignupRequest{
					Username: uniqueUsername,
					Password: "testpass123",
				}
				signupResp, err := service.SignupUser(context.Background(), &signupReq)
				require.NoError(suite.T(), err, "Setup user should succeed")

				userIDFromToken, err := service.validateJWT(signupResp.Token)
				require.NoError(suite.T(), err, "Should validate JWT")
				tt.userID = userIDFromToken

				for i := 0; i < 5; i++ {
					extractReq := api.LLMAnalysisRequest{
						Text: fmt.Sprintf("This is analysis number %d for testing pagination and retrieval functionality.", i),
					}
					_, err := service.ExtractKnowledge(context.Background(), &extractReq, userIDFromToken)
					require.NoError(suite.T(), err, "Should create analysis")
				}
			}

			response, err := service.GetKnowledgeEntries(context.Background(), tt.userID, tt.page, tt.limit)

			if tt.expectError {
				assert.Error(suite.T(), err, "Expected error for test case: %s", tt.name)
				assert.Nil(suite.T(), response, "Response should be nil on error")
			} else {
				assert.NoError(suite.T(), err, "Expected no error for test case: %s", tt.name)
				assert.NotNil(suite.T(), response, "Response should not be nil on success")
				assert.Equal(suite.T(), tt.page, response.CurrentPage, "Current page should match")
				assert.GreaterOrEqual(suite.T(), response.TotalPages, 1, "Total pages should be at least 1")
				assert.GreaterOrEqual(suite.T(), response.TotalCount, 0, "Total count should be non-negative")
			}
		})
	}
}

func (suite *ServiceTestSuite) TestServiceDeleteKnowledgeEntry() {
	tests := []struct {
		name        string
		setupData   bool
		userID      uuid.UUID
		analysisID  uuid.UUID
		expectError bool
		errorMsg    string
	}{
		{
			name:        "should delete knowledge entry successfully",
			setupData:   true,
			userID:      uuid.New(),
			analysisID:  uuid.New(),
			expectError: false,
		},
		{
			name:        "should fail with non-existent analysis",
			setupData:   false,
			userID:      uuid.New(),
			analysisID:  uuid.New(),
			expectError: true,
			errorMsg:    "analysis not found",
		},
		{
			name:        "should fail with wrong user",
			setupData:   true,
			userID:      uuid.New(),
			analysisID:  uuid.New(),
			expectError: true,
			errorMsg:    "access denied",
		},
	}

	for _, tt := range tests {
		suite.Run(tt.name, func() {
			conf := &config.Security{
				PasswordSalt: "test-salt",
				JWTSecret:    "test-secret",
				TokenExpiry:  24,
			}
			mockLLM := createMockLLM()
			service := NewService(&suite.log, conf, mockLLM, suite.dao)

			if tt.setupData {
				// Setup user and create analysis
				uniqueUsername := fmt.Sprintf("testuser_%d", time.Now().UnixNano())
				signupReq := api.SignupRequest{
					Username: uniqueUsername,
					Password: "testpass123",
				}
				signupResp, err := service.SignupUser(context.Background(), &signupReq)
				require.NoError(suite.T(), err, "Setup user should succeed")

				userIDFromToken, err := service.validateJWT(signupResp.Token)
				require.NoError(suite.T(), err, "Should validate JWT")

				extractReq := api.LLMAnalysisRequest{
					Text: "This is a test analysis for deletion testing.",
				}
				extractResp, err := service.ExtractKnowledge(context.Background(), &extractReq, userIDFromToken)
				require.NoError(suite.T(), err, "Should create analysis")

				if tt.name == "should fail with wrong user" {
					// Create a different user to attempt deletion
					wrongUsername := fmt.Sprintf("wronguser_%d", time.Now().UnixNano())
					wrongSignupReq := api.SignupRequest{
						Username: wrongUsername,
						Password: "testpass123",
					}
					wrongSignupResp, err := service.SignupUser(context.Background(), &wrongSignupReq)
					require.NoError(suite.T(), err, "Setup wrong user should succeed")

					wrongUserIDFromToken, err := service.validateJWT(wrongSignupResp.Token)
					require.NoError(suite.T(), err, "Should validate wrong user JWT")
					tt.userID = wrongUserIDFromToken
				} else {
					tt.userID = userIDFromToken
				}
				tt.analysisID = extractResp.ID
			}

			err := service.DeleteKnowledgeEntry(context.Background(), tt.analysisID, tt.userID)

			if tt.expectError {
				assert.Error(suite.T(), err, "Expected error for test case: %s", tt.name)
				if tt.errorMsg != "" {
					assert.Contains(suite.T(), err.Error(), tt.errorMsg, "Expected error message to contain: %s", tt.errorMsg)
				}
			} else {
				assert.NoError(suite.T(), err, "Expected no error for test case: %s", tt.name)
			}
		})
	}
}

func TestServiceTestSuite(t *testing.T) {
	suite.Run(t, new(ServiceTestSuite))
}
