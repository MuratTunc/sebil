package middleware

import (
	"authentication-service/src/config"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"
	"github.com/go-chi/httprate"
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

func (m *Middleware) RateLimiterMiddleware() func(http.Handler) http.Handler {
	// Limit each IP to 100 requests per 1 minute (can tune per endpoint later)
	return httprate.LimitByIP(100, 1*time.Minute)
}

// SetupMiddleware sets up all global middleware
func (m *Middleware) SetupMiddleware(mux *chi.Mux) {

	mux.Use(m.CORSMiddleware())
	mux.Use(middleware.Heartbeat("/ping"))
	mux.Use(middleware.Recoverer)
	mux.Use(middleware.Logger)

	// Add global rate limiting
	mux.Use(m.RateLimiterMiddleware())

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
