package internal

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"go.ssnk.in/joustlm/config"
	"go.ssnk.in/joustlm/logger"
)

func TestNewServer(t *testing.T) {
	log := logger.New(logger.SetLevel(logger.Debug))
	conf := &config.Server{}
	handler := &Handler{}
	server := NewServer(&log, conf, handler)

	if server == nil {
		t.Error("NewServer should not return nil")
	}
	if server.logger != &log {
		t.Error("Logger should be set correctly")
	}
	if server.config != conf {
		t.Error("Config should be set correctly")
	}
	if server.handler != handler {
		t.Error("Handler should be set correctly")
	}
	if server.router == nil {
		t.Error("Router should be initialized")
	}
}

func TestServerRegisterRoutes(t *testing.T) {
	log := logger.New(logger.SetLevel(logger.Debug))
	conf := &config.Server{
		Port: "8080",
		CORS: config.CORS{
			AllowedOrigins:   []string{"*"},
			AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
			AllowedHeaders:   []string{"*"},
			AllowCredentials: false,
			ExposeHeaders:    []string{},
			MaxAge:           3600,
		},
		FrontendAssetsPath: "frontend",
	}
	service := &Service{}
	handler := NewHandler(&log, service)
	server := NewServer(&log, conf, handler)

	// Register routes
	server.RegisterRoutes(handler, service)

	// Test health endpoint
	req := httptest.NewRequest("GET", "/health", nil)
	w := httptest.NewRecorder()
	server.router.ServeHTTP(w, req)

	// Should call the health handler
	if w.Code != http.StatusOK {
		t.Errorf("Expected status %d, got %d", http.StatusOK, w.Code)
	}
}

func TestServerHealthEndpoint(t *testing.T) {
	log := logger.New(logger.SetLevel(logger.Debug))
	conf := &config.Server{
		Port: "8080",
		CORS: config.CORS{
			AllowedOrigins:   []string{"*"},
			AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
			AllowedHeaders:   []string{"*"},
			AllowCredentials: false,
			ExposeHeaders:    []string{},
			MaxAge:           3600,
		},
		FrontendAssetsPath: "frontend",
	}
	service := &Service{}
	handler := NewHandler(&log, service)
	server := NewServer(&log, conf, handler)
	server.RegisterRoutes(handler, service)

	req := httptest.NewRequest("GET", "/health", nil)
	w := httptest.NewRecorder()
	server.router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status %d, got %d", http.StatusOK, w.Code)
	}
}
