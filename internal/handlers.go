package internal

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"go.ssnk.in/joustlm/logger"
	"go.ssnk.in/joustlm/pkg"
	"go.ssnk.in/joustlm/schema/api"
)

type Handler struct {
	logger  *logger.Logger
	service *Service
}

func NewHandler(logger *logger.Logger, service *Service) *Handler {
	return &Handler{
		logger:  logger,
		service: service,
	}
}

func (h *Handler) HandleHealth(w http.ResponseWriter, r *http.Request) {
	h.logger.Debug("Health check requested")
	pkg.SendJSONResponse(w, http.StatusOK, api.HealthResponse{
		Status:    api.HealthStatusOK,
		Timestamp: time.Now().Format(time.RFC3339),
	})
}

func (h *Handler) GetLLMMetrics(w http.ResponseWriter, r *http.Request) {
	h.logger.Debug("LLM metrics request received")

	metrics, err := h.service.GetLLMMetrics()
	if err != nil {
		h.logger.Error("Failed to get LLM metrics", "error", err)
		pkg.SendError(w, http.StatusInternalServerError)
		return
	}

	pkg.SendJSONResponse(w, http.StatusOK, metrics)
}

func (h *Handler) Signup(w http.ResponseWriter, r *http.Request) {
	h.logger.Debug("Signup request received")

	var req api.SignupRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.logger.Debug("Failed to decode signup request", "error", err)
		h.logger.Error("Failed to decode signup request", "error", err)
		pkg.SendError(w, http.StatusBadRequest)
		return
	}

	if req.Username == "" || req.Password == "" {
		h.logger.Debug("Invalid signup request - missing fields", "username", req.Username)
		pkg.SendError(w, http.StatusBadRequest)
		return
	}

	if len(req.Password) < 6 {
		h.logger.Debug("Invalid signup request - password too short", "username", req.Username)
		pkg.SendError(w, http.StatusBadRequest)
		return
	}

	response, err := h.service.SignupUser(&req)
	if err != nil {
		h.logger.Debug("Signup service failed", "error", err, "username", req.Username)
		h.logger.Error("Signup failed", "error", err, "username", req.Username)
		if err.Error() == "username already exists" {
			pkg.SendError(w, http.StatusConflict)
		} else {
			pkg.SendError(w, http.StatusInternalServerError)
		}
		return
	}

	h.logger.Debug("Signup successful", "username", req.Username)
	pkg.SendJSONResponse(w, http.StatusCreated, response)
}

func (h *Handler) Login(w http.ResponseWriter, r *http.Request) {
	h.logger.Debug("Login request received")

	var req api.LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.logger.Debug("Failed to decode login request", "error", err)
		h.logger.Error("Failed to decode login request", "error", err)
		pkg.SendError(w, http.StatusBadRequest)
		return
	}
	if req.Username == "" || req.Password == "" {
		h.logger.Debug("Invalid login request - missing fields", "username", req.Username)
		pkg.SendError(w, http.StatusBadRequest)
		return
	}
	response, err := h.service.LoginUser(&req)
	if err != nil {
		h.logger.Debug("Login service failed", "error", err, "username", req.Username)
		h.logger.Error("Login failed", "error", err, "username", req.Username)
		if err.Error() == "invalid credentials" {
			pkg.SendError(w, http.StatusUnauthorized)
		} else {
			pkg.SendError(w, http.StatusInternalServerError)
		}
		return
	}

	h.logger.Debug("Login successful", "username", req.Username)
	pkg.SendJSONResponse(w, http.StatusOK, response)
}

func (h *Handler) Logout(w http.ResponseWriter, r *http.Request) {
	h.logger.Debug("Logout request received")

	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		h.logger.Debug("Logout failed - no authorization header")
		pkg.SendError(w, http.StatusUnauthorized)
		return
	}
	tokenParts := strings.Split(authHeader, " ")
	if len(tokenParts) != 2 || tokenParts[0] != "Bearer" {
		h.logger.Debug("Logout failed - invalid authorization format")
		pkg.SendError(w, http.StatusUnauthorized)
		return
	}

	token := tokenParts[1]
	err := h.service.LogoutUser(token)
	if err != nil {
		h.logger.Debug("Logout service failed", "error", err)
		h.logger.Error("Logout failed", "error", err)
		if err.Error() == "invalid token" {
			pkg.SendError(w, http.StatusUnauthorized)
		} else {
			pkg.SendError(w, http.StatusInternalServerError)
		}
		return
	}

	h.logger.Debug("Logout successful")
	pkg.SendNoContentResponse(w)
}

func (h *Handler) ExtractKnowledge(w http.ResponseWriter, r *http.Request) {
	h.logger.Debug("Extract knowledge request received")

	userID, ok := r.Context().Value(contextKey("userID")).(uuid.UUID)
	if !ok {
		h.logger.Debug("Extract knowledge failed - no user ID in context")
		pkg.SendError(w, http.StatusUnauthorized)
		return
	}

	var req api.LLMAnalysisRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.logger.Debug("Failed to decode extract knowledge request", "error", err)
		h.logger.Error("Failed to decode extract knowledge request", "error", err)
		pkg.SendError(w, http.StatusBadRequest)
		return
	}

	if req.Text == "" {
		h.logger.Debug("Extract knowledge failed - empty text")
		pkg.SendError(w, http.StatusBadRequest)
		return
	}

	if err := pkg.ValidateText(req.Text); err != nil {
		h.logger.Debug("Extract knowledge failed - text validation", "error", err)
		pkg.SendError(w, http.StatusBadRequest)
		return
	}

	h.logger.Debug("Extracting knowledge", "user_id", userID, "text_length", len(req.Text))

	response, err := h.service.ExtractKnowledge(&req, userID)
	if err != nil {
		h.logger.Debug("Extract knowledge service failed", "error", err, "user_id", userID)
		h.logger.Error("Extract knowledge failed", "error", err, "user_id", userID)
		if err.Error() == "text cannot be empty" {
			pkg.SendError(w, http.StatusBadRequest)
		} else {
			pkg.SendError(w, http.StatusInternalServerError)
		}
		return
	}

	h.logger.Debug("Extract knowledge successful", "user_id", userID, "analysis_id", response.ID)
	pkg.SendJSONResponse(w, http.StatusOK, response)
}

func (h *Handler) GetExtractionResult(w http.ResponseWriter, r *http.Request) {
	h.logger.Debug("Get extraction result request received")

	userID, ok := r.Context().Value(contextKey("userID")).(uuid.UUID)
	if !ok {
		h.logger.Debug("Get extraction result failed - no user ID in context")
		pkg.SendError(w, http.StatusUnauthorized)
		return
	}

	if err := pkg.ValidatePathSegments(r.URL.Path, 4); err != nil {
		h.logger.Debug("Get extraction result failed - invalid path", "path", r.URL.Path, "error", err)
		pkg.SendError(w, http.StatusBadRequest)
		return
	}

	pathParts := strings.Split(r.URL.Path, "/")
	analysisIDStr := pathParts[4]
	analysisID, err := uuid.Parse(analysisIDStr)
	if err != nil {
		h.logger.Debug("Get extraction result failed - invalid analysis ID", "analysis_id_str", analysisIDStr, "error", err)
		pkg.SendError(w, http.StatusBadRequest)
		return
	}

	h.logger.Debug("Getting extraction result", "user_id", userID, "analysis_id", analysisID)

	response, err := h.service.GetExtractionResult(analysisID, userID)
	if err != nil {
		h.logger.Debug("Get extraction result service failed", "error", err, "user_id", userID, "analysis_id", analysisID)
		h.logger.Error("Get extraction result failed", "error", err, "user_id", userID, "analysis_id", analysisID)
		if err.Error() == "analysis not found" || err.Error() == "access denied" {
			pkg.SendError(w, http.StatusNotFound)
		} else {
			pkg.SendError(w, http.StatusInternalServerError)
		}
		return
	}

	h.logger.Debug("Get extraction result successful", "user_id", userID, "analysis_id", analysisID)
	pkg.SendJSONResponse(w, http.StatusOK, response)
}

func (h *Handler) GetKnowledgeEntries(w http.ResponseWriter, r *http.Request) {
	h.logger.Debug("Get knowledge entries request received")

	userID, ok := r.Context().Value(contextKey("userID")).(uuid.UUID)
	if !ok {
		h.logger.Debug("Get knowledge entries failed - no user ID in context")
		pkg.SendError(w, http.StatusUnauthorized)
		return
	}

	page := 1
	limit := 10

	if pageStr := r.URL.Query().Get("page"); pageStr != "" {
		if p, err := strconv.Atoi(pageStr); err == nil && p > 0 {
			page = p
		}
	}

	if limitStr := r.URL.Query().Get("limit"); limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil && l > 0 && l <= 100 {
			limit = l
		}
	}

	h.logger.Debug("Getting knowledge entries", "user_id", userID, "page", page, "limit", limit)

	response, err := h.service.GetKnowledgeEntries(userID, page, limit)
	if err != nil {
		h.logger.Debug("Get knowledge entries service failed", "error", err, "user_id", userID)
		h.logger.Error("Get knowledge entries failed", "error", err, "user_id", userID)
		pkg.SendError(w, http.StatusInternalServerError)
		return
	}

	h.logger.Debug("Get knowledge entries successful", "user_id", userID, "count", len(response.Knowledge))
	pkg.SendJSONResponse(w, http.StatusOK, response)
}

func (h *Handler) CreateKnowledgeEntry(w http.ResponseWriter, r *http.Request) {
	h.logger.Debug("Create knowledge entry request received")

	userID, ok := r.Context().Value(contextKey("userID")).(uuid.UUID)
	if !ok {
		h.logger.Debug("Create knowledge entry failed - no user ID in context")
		pkg.SendError(w, http.StatusUnauthorized)
		return
	}

	var req api.CreateKnowledgeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.logger.Debug("Failed to decode create knowledge entry request", "error", err)
		h.logger.Error("Failed to decode create knowledge entry request", "error", err)
		pkg.SendError(w, http.StatusBadRequest)
		return
	}

	if req.Text == "" || req.Summary == "" || len(req.Topics) == 0 || req.Sentiment == "" || len(req.Keywords) == 0 {
		h.logger.Debug("Create knowledge entry failed - missing required fields")
		pkg.SendError(w, http.StatusBadRequest)
		return
	}

	// Validate input data
	if err := pkg.ValidateText(req.Text); err != nil {
		h.logger.Debug("Create knowledge entry failed - text validation", "error", err)
		pkg.SendError(w, http.StatusBadRequest)
		return
	}

	if err := pkg.ValidateSummary(req.Summary); err != nil {
		h.logger.Debug("Create knowledge entry failed - summary validation", "error", err)
		pkg.SendError(w, http.StatusBadRequest)
		return
	}

	if err := pkg.ValidateTopics(req.Topics); err != nil {
		h.logger.Debug("Create knowledge entry failed - topics validation", "error", err)
		pkg.SendError(w, http.StatusBadRequest)
		return
	}

	if err := pkg.ValidateKeywords(req.Keywords); err != nil {
		h.logger.Debug("Create knowledge entry failed - keywords validation", "error", err)
		pkg.SendError(w, http.StatusBadRequest)
		return
	}

	if err := pkg.ValidateSentiment(req.Sentiment); err != nil {
		h.logger.Debug("Create knowledge entry failed - sentiment validation", "error", err)
		pkg.SendError(w, http.StatusBadRequest)
		return
	}

	if err := pkg.ValidateConfidence(req.Confidence); err != nil {
		h.logger.Debug("Create knowledge entry failed - confidence validation", "error", err)
		pkg.SendError(w, http.StatusBadRequest)
		return
	}

	if err := pkg.ValidateTitle(req.Title); err != nil {
		h.logger.Debug("Create knowledge entry failed - title validation", "error", err)
		pkg.SendError(w, http.StatusBadRequest)
		return
	}

	h.logger.Debug("Creating knowledge entry", "user_id", userID)

	response, err := h.service.CreateKnowledgeEntry(&req, userID)
	if err != nil {
		h.logger.Debug("Create knowledge entry service failed", "error", err, "user_id", userID)
		h.logger.Error("Create knowledge entry failed", "error", err, "user_id", userID)
		pkg.SendError(w, http.StatusInternalServerError)
		return
	}

	h.logger.Debug("Create knowledge entry successful", "user_id", userID, "entry_id", response.ID)
	pkg.SendJSONResponse(w, http.StatusCreated, response)
}

func (h *Handler) UpdateKnowledgeEntry(w http.ResponseWriter, r *http.Request) {
	h.logger.Debug("Update knowledge entry request received")

	userID, ok := r.Context().Value(contextKey("userID")).(uuid.UUID)
	if !ok {
		h.logger.Debug("Update knowledge entry failed - no user ID in context")
		pkg.SendError(w, http.StatusUnauthorized)
		return
	}

	if err := pkg.ValidatePathSegments(r.URL.Path, 4); err != nil {
		h.logger.Debug("Update knowledge entry failed - invalid path", "path", r.URL.Path, "error", err)
		pkg.SendError(w, http.StatusBadRequest)
		return
	}

	pathParts := strings.Split(r.URL.Path, "/")
	entryIDStr := pathParts[4]
	entryID, err := uuid.Parse(entryIDStr)
	if err != nil {
		h.logger.Debug("Update knowledge entry failed - invalid entry ID", "entry_id_str", entryIDStr, "error", err)
		pkg.SendError(w, http.StatusBadRequest)
		return
	}

	var req api.UpdateKnowledgeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.logger.Debug("Failed to decode update knowledge entry request", "error", err)
		h.logger.Error("Failed to decode update knowledge entry request", "error", err)
		pkg.SendError(w, http.StatusBadRequest)
		return
	}

	h.logger.Debug("Updating knowledge entry", "user_id", userID, "entry_id", entryID)

	response, err := h.service.UpdateKnowledgeEntry(entryID, &req, userID)
	if err != nil {
		h.logger.Debug("Update knowledge entry service failed", "error", err, "user_id", userID, "entry_id", entryID)
		h.logger.Error("Update knowledge entry failed", "error", err, "user_id", userID, "entry_id", entryID)
		if err.Error() == "analysis not found" || err.Error() == "access denied" {
			pkg.SendError(w, http.StatusNotFound)
		} else {
			pkg.SendError(w, http.StatusInternalServerError)
		}
		return
	}

	h.logger.Debug("Update knowledge entry successful", "user_id", userID, "entry_id", entryID)
	pkg.SendJSONResponse(w, http.StatusOK, response)
}

func (h *Handler) DeleteKnowledgeEntry(w http.ResponseWriter, r *http.Request) {
	h.logger.Debug("Delete knowledge entry request received")

	userID, ok := r.Context().Value(contextKey("userID")).(uuid.UUID)
	if !ok {
		h.logger.Debug("Delete knowledge entry failed - no user ID in context")
		pkg.SendError(w, http.StatusUnauthorized)
		return
	}

	if err := pkg.ValidatePathSegments(r.URL.Path, 4); err != nil {
		h.logger.Debug("Delete knowledge entry failed - invalid path", "path", r.URL.Path, "error", err)
		pkg.SendError(w, http.StatusBadRequest)
		return
	}

	pathParts := strings.Split(r.URL.Path, "/")
	entryIDStr := pathParts[4]
	entryID, err := uuid.Parse(entryIDStr)
	if err != nil {
		h.logger.Debug("Delete knowledge entry failed - invalid entry ID", "entry_id_str", entryIDStr, "error", err)
		pkg.SendError(w, http.StatusBadRequest)
		return
	}

	h.logger.Debug("Deleting knowledge entry", "user_id", userID, "entry_id", entryID)

	err = h.service.DeleteKnowledgeEntry(entryID, userID)
	if err != nil {
		h.logger.Debug("Delete knowledge entry service failed", "error", err, "user_id", userID, "entry_id", entryID)
		h.logger.Error("Delete knowledge entry failed", "error", err, "user_id", userID, "entry_id", entryID)
		if err.Error() == "analysis not found" || err.Error() == "access denied" {
			pkg.SendError(w, http.StatusNotFound)
		} else {
			pkg.SendError(w, http.StatusInternalServerError)
		}
		return
	}

	h.logger.Debug("Delete knowledge entry successful", "user_id", userID, "entry_id", entryID)
	pkg.SendNoContentResponse(w)
}

func (h *Handler) SearchKnowledge(w http.ResponseWriter, r *http.Request) {
	h.logger.Debug("Search knowledge request received")

	userID, ok := r.Context().Value(contextKey("userID")).(uuid.UUID)
	if !ok {
		h.logger.Debug("Search knowledge failed - no user ID in context")
		pkg.SendError(w, http.StatusUnauthorized)
		return
	}

	page := 1
	limit := 10
	topic := r.URL.Query().Get("topic")
	keyword := r.URL.Query().Get("keyword")
	sentiment := r.URL.Query().Get("sentiment")

	if pageStr := r.URL.Query().Get("page"); pageStr != "" {
		if p, err := strconv.Atoi(pageStr); err == nil && p > 0 {
			page = p
		}
	}

	if limitStr := r.URL.Query().Get("limit"); limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil && l > 0 && l <= 100 {
			limit = l
		}
	}

	req := &api.SearchRequest{
		Topic:     topic,
		Keyword:   keyword,
		Sentiment: sentiment,
		Page:      page,
		Limit:     limit,
	}

	h.logger.Debug("Searching knowledge", "user_id", userID, "topic", topic, "keyword", keyword, "sentiment", sentiment)

	response, err := h.service.SearchKnowledge(req, userID)
	if err != nil {
		h.logger.Debug("Search knowledge service failed", "error", err, "user_id", userID)
		h.logger.Error("Search knowledge failed", "error", err, "user_id", userID)
		pkg.SendError(w, http.StatusInternalServerError)
		return
	}

	h.logger.Debug("Search knowledge successful", "user_id", userID, "count", len(response.Results))
	pkg.SendJSONResponse(w, http.StatusOK, response)
}
