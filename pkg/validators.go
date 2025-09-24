package pkg

import (
	"strings"

	"github.com/google/uuid"
)

func ExtractUUIDFromPath(path string, position int) (uuid.UUID, error) {
	parts := strings.Split(strings.Trim(path, "/"), "/")

	if position < 0 || position >= len(parts) {
		return uuid.Nil, &ValidationError{Message: "position out of bounds"}
	}

	id, err := uuid.Parse(parts[position])
	if err != nil {
		return uuid.Nil, &ValidationError{Message: "invalid UUID format", Cause: err}
	}

	return id, nil
}

func ExtractUUIDFromLastSegment(path string) (uuid.UUID, error) {
	parts := strings.Split(strings.Trim(path, "/"), "/")
	if len(parts) == 0 {
		return uuid.Nil, &ValidationError{Message: "empty path"}
	}

	return ExtractUUIDFromPath(path, len(parts)-1)
}

func ExtractUUIDAfterSegment(path string, segment string) (uuid.UUID, bool) {
	parts := strings.Split(strings.Trim(path, "/"), "/")

	for i, p := range parts {
		if p == segment && i+1 < len(parts) {
			id, err := uuid.Parse(parts[i+1])
			if err == nil {
				return id, true
			}
		}
	}

	return uuid.Nil, false
}
func ExtractTwoUUIDsAfterSegments(path string, firstSegment, secondSegment string) (uuid.UUID, uuid.UUID, bool) {
	parts := strings.Split(strings.Trim(path, "/"), "/")

	for i, p := range parts {
		if p == firstSegment && i+3 < len(parts) && parts[i+2] == secondSegment {
			firstID, err := uuid.Parse(parts[i+1])
			if err != nil {
				return uuid.Nil, uuid.Nil, false
			}

			secondID, err := uuid.Parse(parts[i+3])
			if err != nil {
				return uuid.Nil, uuid.Nil, false
			}

			return firstID, secondID, true
		}
	}

	return uuid.Nil, uuid.Nil, false
}
func ValidatePathSegments(path string, expectedMinSegments int) error {
	parts := strings.Split(strings.Trim(path, "/"), "/")
	if len(parts) < expectedMinSegments {
		return &ValidationError{Message: "insufficient path segments"}
	}

	return nil
}

func ValidateText(text string) error {
	if text == "" {
		return &ValidationError{Message: "text cannot be empty"}
	}

	if len(text) < 10 {
		return &ValidationError{Message: "text must be at least 10 characters long"}
	}

	if len(text) > 100000 {
		return &ValidationError{Message: "text cannot exceed 100,000 characters"}
	}

	return nil
}

func ValidateTopics(topics []string) error {
	if len(topics) == 0 {
		return &ValidationError{Message: "topics cannot be empty"}
	}

	if len(topics) > 3 {
		return &ValidationError{Message: "topics cannot exceed 3 items"}
	}

	for i, topic := range topics {
		if topic == "" {
			return &ValidationError{Message: "topic cannot be empty"}
		}

		if len(topic) > 100 {
			return &ValidationError{Message: "topic cannot exceed 100 characters"}
		}

		for j := i + 1; j < len(topics); j++ {
			if topic == topics[j] {
				return &ValidationError{Message: "duplicate topics are not allowed"}
			}
		}
	}

	return nil
}

func ValidateKeywords(keywords []string) error {
	if len(keywords) == 0 {
		return &ValidationError{Message: "keywords cannot be empty"}
	}

	if len(keywords) > 5 {
		return &ValidationError{Message: "keywords cannot exceed 5 items"}
	}

	for i, keyword := range keywords {
		if keyword == "" {
			return &ValidationError{Message: "keyword cannot be empty"}
		}

		if len(keyword) > 100 {
			return &ValidationError{Message: "keyword cannot exceed 100 characters"}
		}

		for j := i + 1; j < len(keywords); j++ {
			if keyword == keywords[j] {
				return &ValidationError{Message: "duplicate keywords are not allowed"}
			}
		}
	}

	return nil
}

func ValidateSentiment(sentiment string) error {
	validSentiments := []string{"positive", "neutral", "negative"}

	for _, valid := range validSentiments {
		if sentiment == valid {
			return nil
		}
	}

	return &ValidationError{Message: "sentiment must be one of: positive, neutral, negative"}
}

func ValidateConfidence(confidence float64) error {
	if confidence < 0.0 || confidence > 1.0 {
		return &ValidationError{Message: "confidence must be between 0.0 and 1.0"}
	}

	return nil
}

func ValidateSummary(summary string) error {
	if summary == "" {
		return &ValidationError{Message: "summary cannot be empty"}
	}

	if len(summary) < 10 {
		return &ValidationError{Message: "summary must be at least 10 characters long"}
	}

	if len(summary) > 500 {
		return &ValidationError{Message: "summary cannot exceed 500 characters"}
	}

	return nil
}

func ValidateTitle(title string) error {
	if title != "" && len(title) > 200 {
		return &ValidationError{Message: "title cannot exceed 200 characters"}
	}

	return nil
}

type ValidationError struct {
	Message string
	Cause   error
}

func (e *ValidationError) Error() string {
	if e.Cause != nil {
		return e.Message + ": " + e.Cause.Error()
	}
	return e.Message
}
