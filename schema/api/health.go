package api

const (
	HealthStatusOK      = "OK"
	HealthStatusError   = "ERROR"
	HealthStatusWarning = "WARNING"
)

type HealthResponse struct {
	Status    string `json:"status"`
	Timestamp string `json:"timestamp"`
	Version   string `json:"version,omitempty"`
}
