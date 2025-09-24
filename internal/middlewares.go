package internal

import (
	"context"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"go.ssnk.in/joustlm/config"
	"go.ssnk.in/joustlm/logger"
	"go.ssnk.in/joustlm/pkg"
)

type contextKey string

func MLogging(logger *logger.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			logger.Info("Request started",
				"method", r.Method,
				"path", r.URL.Path,
				"remote_addr", r.RemoteAddr,
				"user_agent", r.UserAgent())
			rw := &responseWriter{
				ResponseWriter: w,
				statusCode:     http.StatusOK,
			}
			next.ServeHTTP(rw, r)
			duration := time.Since(start)
			logger.Info("Request completed",
				"method", r.Method,
				"path", r.URL.Path,
				"status", rw.statusCode,
				"duration", duration)
		})
	}
}

type responseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}
func MCors(cfg *config.CORS) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			origin := r.Header.Get("Origin")

			if r.Method == http.MethodOptions {
				if origin != "" {
					w.Header().Set("Access-Control-Allow-Origin", origin)
				} else {
					w.Header().Set("Access-Control-Allow-Origin", "*")
				}
				w.Header().Set("Access-Control-Allow-Methods", strings.Join(cfg.AllowedMethods, ", "))
				w.Header().Set("Access-Control-Allow-Headers", strings.Join(cfg.AllowedHeaders, ", "))
				w.Header().Set("Access-Control-Allow-Credentials", strconv.FormatBool(cfg.AllowCredentials))
				if cfg.MaxAge > 0 {
					w.Header().Set("Access-Control-Max-Age", strconv.Itoa(cfg.MaxAge))
				}
				w.WriteHeader(http.StatusOK)
				return
			}

			if origin != "" {
				originAllowed := false
				for _, allowedOrigin := range cfg.AllowedOrigins {
					if allowedOrigin == "*" {
						w.Header().Set("Access-Control-Allow-Origin", "*")
						originAllowed = true
						break
					} else if strings.Contains(allowedOrigin, "*") {
						pattern := strings.ReplaceAll(allowedOrigin, "*", ".*")
						if matched, _ := regexp.MatchString(pattern, origin); matched {
							w.Header().Set("Access-Control-Allow-Origin", origin)
							originAllowed = true
							break
						}
					} else if origin == allowedOrigin {
						w.Header().Set("Access-Control-Allow-Origin", origin)
						originAllowed = true
						break
					}
				}

				if !originAllowed && !cfg.AllowCredentials {
					w.Header().Set("Access-Control-Allow-Origin", "*")
				}
			} else {
				w.Header().Set("Access-Control-Allow-Origin", "*")
			}

			w.Header().Set("Access-Control-Allow-Methods", strings.Join(cfg.AllowedMethods, ", "))
			w.Header().Set("Access-Control-Allow-Headers", strings.Join(cfg.AllowedHeaders, ", "))
			w.Header().Set("Access-Control-Expose-Headers", strings.Join(cfg.ExposeHeaders, ", "))
			w.Header().Set("Access-Control-Allow-Credentials", strconv.FormatBool(cfg.AllowCredentials))

			next.ServeHTTP(w, r)
		})
	}
}

func MAuth(service *Service) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

			authHeader := r.Header.Get("Authorization")
			if authHeader == "" {
				pkg.SendError(w, http.StatusUnauthorized)
				return
			}
			tokenParts := strings.Split(authHeader, " ")
			if len(tokenParts) != 2 || tokenParts[0] != "Bearer" {
				pkg.SendError(w, http.StatusUnauthorized)
				return
			}

			token := tokenParts[1]
			userID, err := service.validateJWT(token)
			if err != nil {
				pkg.SendError(w, http.StatusUnauthorized)
				return
			}

			ctx := context.WithValue(r.Context(), contextKey("userID"), userID)
			r = r.WithContext(ctx)

			next.ServeHTTP(w, r)
		})
	}
}
