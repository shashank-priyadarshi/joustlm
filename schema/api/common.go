package api

const (
	DefaultPage  = 1
	DefaultLimit = 10
	MaxLimit     = 100
)

type NoContentResponse struct{}

type CommonResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message,omitempty"`
	Data    any    `json:"data,omitempty"`
}
