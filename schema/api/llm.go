package api

import (
	"time"

	"github.com/google/uuid"
)

type LLMAnalysisRequest struct {
	Text string `json:"text" validate:"required"`
}

type LLMAnalysisResponse struct {
	ID          uuid.UUID `json:"id"`
	Text        string    `json:"text"`
	Title       string    `json:"title,omitempty"`
	Summary     string    `json:"summary"`
	Topics      []string  `json:"topics"`
	Sentiment   string    `json:"sentiment"`
	Keywords    []string  `json:"keywords"`
	Confidence  float64   `json:"confidence"`
	CreatedAt   time.Time `json:"created_at"`
	Error       string    `json:"error,omitempty"`
}

type KnowledgeBaseEntry struct {
	ID          uuid.UUID `json:"id"`
	UserID      uuid.UUID `json:"user_id"`
	Text        string    `json:"text"`
	Title       string    `json:"title,omitempty"`
	Summary     string    `json:"summary"`
	Topics      []string  `json:"topics"`
	Sentiment   string    `json:"sentiment"`
	Keywords    []string  `json:"keywords"`
	Confidence  float64   `json:"confidence"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

type CreateKnowledgeRequest struct {
	Text       string   `json:"text" validate:"required"`
	Title      string   `json:"title,omitempty"`
	Summary    string   `json:"summary" validate:"required"`
	Topics     []string `json:"topics" validate:"required"`
	Sentiment  string   `json:"sentiment" validate:"required"`
	Keywords   []string `json:"keywords" validate:"required"`
	Confidence float64  `json:"confidence"`
}

type UpdateKnowledgeRequest struct {
	Title      string   `json:"title,omitempty"`
	Summary    string   `json:"summary,omitempty"`
	Topics     []string `json:"topics,omitempty"`
	Sentiment  string   `json:"sentiment,omitempty"`
	Keywords   []string `json:"keywords,omitempty"`
	Confidence float64  `json:"confidence,omitempty"`
}

type GetKnowledgeResponse struct {
	Knowledge   []KnowledgeBaseEntry `json:"knowledge"`
	CurrentPage int                  `json:"currentPage"`
	TotalPages  int                  `json:"totalPages"`
	TotalCount  int                  `json:"totalCount"`
}

type SearchRequest struct {
	Topic     string `json:"topic" form:"topic"`
	Keyword   string `json:"keyword" form:"keyword"`
	Sentiment string `json:"sentiment" form:"sentiment"`
	Page      int    `json:"page" form:"page"`
	Limit     int    `json:"limit" form:"limit"`
}

type SearchResponse struct {
	Results     []KnowledgeBaseEntry `json:"results"`
	CurrentPage int                  `json:"currentPage"`
	TotalPages  int                  `json:"totalPages"`
	TotalCount  int                  `json:"totalCount"`
}
