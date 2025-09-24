package internal

import (
	"context"
	"log"

	"github.com/sugarme/tokenizer"
	"go.ssnk.in/joustlm/config"

	"github.com/sugarme/tokenizer/pretrained"
	"google.golang.org/genai"
)

// LLMClient defines the interface for LLM operations
type LLMClient interface {
	Models() LLMModels
}

// LLMModels defines the interface for LLM model operations
type LLMModels interface {
	GenerateContent(ctx context.Context, model string, contents []*genai.Content, config *genai.GenerateContentConfig) (*genai.GenerateContentResponse, error)
}

// genaiClientWrapper wraps the real genai.Client to implement our interface
type genaiClientWrapper struct {
	client *genai.Client
}

func (w *genaiClientWrapper) Models() LLMModels {
	return &genaiModelsWrapper{models: w.client.Models}
}

type genaiModelsWrapper struct {
	models *genai.Models
}

func (w *genaiModelsWrapper) GenerateContent(ctx context.Context, model string, contents []*genai.Content, config *genai.GenerateContentConfig) (*genai.GenerateContentResponse, error) {
	return w.models.GenerateContent(ctx, model, contents, config)
}

type LLM struct {
	summarizer LLMClient
	tokenizer  *tokenizer.Tokenizer
}

func NewLLM(conf *config.LLM) *LLM {
	ctx := context.Background()
	configFile, err := tokenizer.CachedPath("bert-base-uncased", "tokenizer.json")
	if err != nil {
		log.Fatalf("Failed to get tokenizer path: %v", err)
	}

	tk, err := pretrained.FromFile(configFile)
	if err != nil {
		panic(err)
	}

	config := &genai.ClientConfig{
		APIKey:  conf.Summarizer.APIKey,
		Backend: genai.BackendGeminiAPI,
	}

	client, err := genai.NewClient(ctx, config)
	if err != nil {
		log.Fatalf("Failed to create client: %v", err)
	}

	return &LLM{
		summarizer: &genaiClientWrapper{client: client},
		tokenizer:  tk,
	}
}
