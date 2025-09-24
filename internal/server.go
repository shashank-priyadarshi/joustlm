package internal

import (
	"fmt"
	"net/http"

	"strings"

	"go.ssnk.in/joustlm/config"
	"go.ssnk.in/joustlm/logger"
	"go.ssnk.in/joustlm/pkg"
)

type Server struct {
	logger  *logger.Logger
	config  *config.Server
	router  *http.ServeMux
	handler *Handler
}

func NewServer(logger *logger.Logger, config *config.Server, handler *Handler) *Server {

	return &Server{
		config:  config,
		router:  http.NewServeMux(),
		logger:  logger,
		handler: handler,
	}
}
func (s *Server) Start() error {
	port := s.config.Port
	if port == "" {
		port = "8080"
	}
	server := &http.Server{
		Addr:    fmt.Sprintf(":%s", port),
		Handler: s.router,
	}

	s.logger.Info("Server starting", "port", port)
	return server.ListenAndServe()
}
func (s *Server) RegisterRoutes(handler *Handler, service *Service) {
	mLogging := MLogging(s.logger)
	mCORS := MCors(&s.config.CORS)
	mAuth := MAuth(service)

	frontendPath := s.config.FrontendAssetsPath
	if frontendPath == "" {
		frontendPath = "frontend"
	}
	s.logger.Info("Serving frontend assets from", "path", frontendPath)

	s.router.Handle("/health", mLogging(mCORS(http.HandlerFunc(s.handler.HandleHealth))))

	s.router.Handle("/assets/", mLogging(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.FileServer(http.Dir(".")).ServeHTTP(w, r)
	})))

	s.router.Handle("/api", mLogging(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			w.Header().Set("Content-Type", "application/json")
			http.ServeFile(w, r, "assets/openapi.json")
		} else {
			pkg.SendError(w, http.StatusMethodNotAllowed)
		}
	})))

	s.router.Handle("/swagger/", mLogging(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/swagger/" || r.URL.Path == "/swagger/index.html" {
			swaggerHTML := `<!DOCTYPE html>
<html>
<head>
    <title>joustlm API Documentation</title>
    <link rel="stylesheet" type="text/css" href="https://unpkg.com/swagger-ui-dist@5.9.0/swagger-ui.css" />
    <style>
        html { box-sizing: border-box; overflow: -moz-scrollbars-vertical; overflow-y: scroll; }
        *, *:before, *:after { box-sizing: inherit; }
        body { margin:0; background: #fafafa; }
    </style>
</head>
<body>
    <div id="swagger-ui"></div>
    <script src="https://unpkg.com/swagger-ui-dist@5.9.0/swagger-ui-bundle.js"></script>
    <script>
        window.onload = function() {
            SwaggerUIBundle({
                url: '/api',
                dom_id: '#swagger-ui',
                presets: [
                    SwaggerUIBundle.presets.apis,
                    SwaggerUIBundle.presets.standalone
                ]
            });
        };
    </script>
</body>
</html>`
			w.Header().Set("Content-Type", "text/html")
			w.Write([]byte(swaggerHTML))
		} else {
			pkg.SendError(w, http.StatusNotFound)
		}
	})))

	s.router.Handle("/metrics", mLogging(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handler.GetLLMMetrics(w, r)
	})))

	s.router.Handle("/api/v1/auth/", mLogging(mCORS(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.logger.Debug("Auth route", "path", r.URL.Path)
		if strings.Contains(r.URL.Path, "/signup") {
			if r.Method == http.MethodPost {
				s.handler.Signup(w, r)
			} else {
				pkg.SendError(w, http.StatusMethodNotAllowed)
			}
		} else if strings.Contains(r.URL.Path, "/login") {
			handler.Login(w, r)
		} else if strings.Contains(r.URL.Path, "/logout") {
			handler.Logout(w, r)
		} else {
			pkg.SendError(w, http.StatusNotFound)
		}
	}))))

	s.router.Handle("/api/v1/extract", mLogging(mCORS(mAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPost:
			handler.ExtractKnowledge(w, r)
		default:
			pkg.SendError(w, http.StatusMethodNotAllowed)
		}
	})))))

	s.router.Handle("/api/v1/extract/", mLogging(mCORS(mAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			handler.GetExtractionResult(w, r)
		} else {
			pkg.SendError(w, http.StatusMethodNotAllowed)
		}
	})))))

	s.router.Handle("/api/v1/knowledge", mLogging(mCORS(mAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			handler.GetKnowledgeEntries(w, r)
		case http.MethodPost:
			handler.CreateKnowledgeEntry(w, r)
		default:
			pkg.SendError(w, http.StatusMethodNotAllowed)
		}
	})))))

	s.router.Handle("/api/v1/knowledge/", mLogging(mCORS(mAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPut:
			handler.UpdateKnowledgeEntry(w, r)
		case http.MethodDelete:
			handler.DeleteKnowledgeEntry(w, r)
		default:
			pkg.SendError(w, http.StatusMethodNotAllowed)
		}
	})))))

	s.router.Handle("/api/v1/search", mLogging(mCORS(mAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			handler.SearchKnowledge(w, r)
		} else {
			pkg.SendError(w, http.StatusMethodNotAllowed)
		}
	})))))

	s.router.Handle("/api/", mLogging(mCORS(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		pkg.SendError(w, http.StatusNotFound)
	}))))

	s.router.Handle("/", mLogging(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			http.ServeFile(w, r, frontendPath+"/index.html")
		} else {
			http.FileServer(http.Dir(frontendPath)).ServeHTTP(w, r)
		}
	})))
}
