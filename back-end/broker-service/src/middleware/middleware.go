package middleware

import (
	"broker-service/src/config"
	"net/http"
	"os"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"
)

type Middleware struct {
	Config *config.Config
}

// NewMiddleware creates a new instance of Middleware
func NewMiddleware(cfg *config.Config) *Middleware {
	return &Middleware{
		Config: cfg,
	}
}

// SetupMiddleware sets up all global middleware
func (m *Middleware) SetupMiddleware(mux *chi.Mux) {

	mux.Use(m.CORSMiddleware())
	mux.Use(middleware.Heartbeat("/ping"))
	mux.Use(middleware.Recoverer)
	mux.Use(middleware.Logger)

	// Log successful initialization of middleware
	m.Config.Logger.Info("✅ Middleware initialized successfully")
}

// CORSMiddleware returns a cors.Handler middleware
func (m *Middleware) CORSMiddleware() func(http.Handler) http.Handler {
	corsOrigins := os.Getenv("BROKER_SERVICE_CORS_ALLOWED_ORIGINS")
	allowedOrigins := strings.Split(corsOrigins, ",")

	// Log CORS setup initialization
	m.Config.Logger.Info("✅ CORS middleware initialized with allowed origins: " + strings.Join(allowedOrigins, ", "))

	return cors.Handler(cors.Options{
		AllowedOrigins:   allowedOrigins,
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type", "X-CSRF-Token"},
		ExposedHeaders:   []string{"Link"},
		AllowCredentials: true,
		MaxAge:           300,
	})
}
