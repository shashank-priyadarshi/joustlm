package pkg

import (
	"encoding/json"
	"net/http"

	"go.ssnk.in/joustlm/schema/api"
)

func SendError(w http.ResponseWriter, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)

	message := getStandardErrorMessage(code)
	json.NewEncoder(w).Encode(api.ErrorResponse{
		Code:    code,
		Message: message,
	})
}

func getStandardErrorMessage(code int) string {
	switch code {
	case http.StatusBadRequest:
		return "Invalid request body"
	case http.StatusUnauthorized:
		return "Unauthorized access"
	case http.StatusForbidden:
		return "Access forbidden"
	case http.StatusNotFound:
		return "Resource not found"
	case http.StatusMethodNotAllowed:
		return "Method not allowed"
	case http.StatusConflict:
		return "Resource conflict"
	case http.StatusUnprocessableEntity:
		return "Validation failed"
	case http.StatusTooManyRequests:
		return "Too many requests"
	case http.StatusInternalServerError:
		return "Internal server error"
	case http.StatusBadGateway:
		return "Bad gateway"
	case http.StatusServiceUnavailable:
		return "Service unavailable"
	case http.StatusGatewayTimeout:
		return "Gateway timeout"
	default:
		return "An error occurred"
	}
}

func SendJSONResponse(w http.ResponseWriter, statusCode int, data interface{}) error {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	return json.NewEncoder(w).Encode(data)
}

func SendNoContentResponse(w http.ResponseWriter) {
	w.WriteHeader(http.StatusNoContent)
}
