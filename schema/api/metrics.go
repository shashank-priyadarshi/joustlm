package api

type MetricsResponse struct {
	Metrics []Metrics `json:"metrics"`
}

type Metrics struct {
	Analyses     int `json:"analyses"`
	Users        int `json:"users"`
	TotalTexts   int `json:"total_texts"`
	AvgConfidence float64 `json:"avg_confidence"`
}
