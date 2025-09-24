package pkg

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"go.ssnk.in/joustlm/schema/api"
)

// LLMClient represents an interface for LLM providers
type LLMClient interface {
	AnalyzeText(text string) (*api.LLMAnalysisResponse, error)
}

// OpenAIClient implements LLMClient for OpenAI GPT models
type OpenAIClient struct {
	APIKey string
	Model  string
	BaseURL string
	Client  *http.Client
}

// NewOpenAIClient creates a new OpenAI client
func NewOpenAIClient(apiKey, model string) *OpenAIClient {
	return &OpenAIClient{
		APIKey:  apiKey,
		Model:   model,
		BaseURL: "https://api.openai.com/v1/chat/completions",
		Client: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// OpenAIRequest represents the request structure for OpenAI API
type OpenAIRequest struct {
	Model    string    `json:"model"`
	Messages []Message `json:"messages"`
	MaxTokens int      `json:"max_tokens"`
	Temperature float64 `json:"temperature"`
}

// Message represents a message in the OpenAI API
type Message struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// OpenAIResponse represents the response structure from OpenAI API
type OpenAIResponse struct {
	Choices []Choice `json:"choices"`
	Error   *APIError `json:"error,omitempty"`
}

// Choice represents a choice in the OpenAI response
type Choice struct {
	Message Message `json:"message"`
}

// APIError represents an API error response
type APIError struct {
	Message string `json:"message"`
	Type    string `json:"type"`
}

// AnalyzeText analyzes text using OpenAI GPT model
func (c *OpenAIClient) AnalyzeText(text string) (*api.LLMAnalysisResponse, error) {
	prompt := fmt.Sprintf(`Analyze the following text and extract structured information:

Text: "%s"

Please provide a JSON response with the following structure:
{
  "title": "A concise title for the text (if applicable)",
  "summary": "A 1-2 sentence summary of the main points",
  "topics": ["topic1", "topic2", "topic3"],
  "sentiment": "positive|neutral|negative",
  "confidence": 0.85
}

Focus on:
- Creating a clear, concise title
- Summarizing the main points in 1-2 sentences
- Identifying exactly 3 key topics
- Determining the overall sentiment
- Providing a confidence score between 0.0 and 1.0

Respond with only the JSON, no additional text.`, text)

	request := OpenAIRequest{
		Model: c.Model,
		Messages: []Message{
			{
				Role:    "system",
				Content: "You are a helpful assistant that extracts structured information from text. Always respond with valid JSON.",
			},
			{
				Role:    "user",
				Content: prompt,
			},
		},
		MaxTokens:   500,
		Temperature: 0.3,
	}

	jsonData, err := json.Marshal(request)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	req, err := http.NewRequest("POST", c.BaseURL, bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.APIKey)

	resp, err := c.Client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		var errorResp OpenAIResponse
		if err := json.NewDecoder(resp.Body).Decode(&errorResp); err == nil && errorResp.Error != nil {
			return nil, fmt.Errorf("OpenAI API error: %s", errorResp.Error.Message)
		}
		return nil, fmt.Errorf("OpenAI API returned status %d", resp.StatusCode)
	}

	var response OpenAIResponse
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	if len(response.Choices) == 0 {
		return nil, fmt.Errorf("no choices in OpenAI response")
	}

	// Parse the JSON response from the LLM
	var llmResult struct {
		Title      string    `json:"title"`
		Summary    string    `json:"summary"`
		Topics     []string  `json:"topics"`
		Sentiment  string    `json:"sentiment"`
		Confidence float64   `json:"confidence"`
	}

	if err := json.Unmarshal([]byte(response.Choices[0].Message.Content), &llmResult); err != nil {
		return nil, fmt.Errorf("failed to parse LLM response: %w", err)
	}

	// Extract keywords using custom algorithm
	keywords := ExtractKeywords(text)

	return &api.LLMAnalysisResponse{
		Text:       text,
		Title:      llmResult.Title,
		Summary:    llmResult.Summary,
		Topics:     llmResult.Topics,
		Sentiment:  llmResult.Sentiment,
		Keywords:   keywords,
		Confidence: llmResult.Confidence,
	}, nil
}

// MockLLMClient implements LLMClient for testing/development
type MockLLMClient struct{}

// NewMockLLMClient creates a new mock LLM client
func NewMockLLMClient() *MockLLMClient {
	return &MockLLMClient{}
}

// AnalyzeText provides mock analysis for testing
func (c *MockLLMClient) AnalyzeText(text string) (*api.LLMAnalysisResponse, error) {
	// Mock response based on text content
	keywords := ExtractKeywords(text)

	title := "Sample Analysis"
	if len(text) > 20 {
		title = text[:20] + "..."
	}

	summary := "This is a mock summary generated for testing purposes. The text has been analyzed and structured data has been extracted."

	topics := []string{"technology", "analysis", "data"}
	if len(text) > 50 {
		topics = []string{"content", "information", "text"}
	}

	sentiment := "neutral"
	if len(text) > 100 {
		sentiment = "positive"
	}

	confidence := 0.85
	if len(text) < 50 {
		confidence = 0.75
	}

	return &api.LLMAnalysisResponse{
		Text:       text,
		Title:      title,
		Summary:    summary,
		Topics:     topics,
		Sentiment:  sentiment,
		Keywords:   keywords,
		Confidence: confidence,
	}, nil
}
