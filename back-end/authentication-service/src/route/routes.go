package route

import (
	"authentication-service/src/config"
	"authentication-service/src/handler"
	"authentication-service/src/middleware"
	"database/sql"
	"net/http"

	"github.com/go-chi/chi/v5"
)

type Routes struct {
	Config     *config.Config
	Handler    *handler.Handler
	Middleware *middleware.Middleware
}

func NewRoutes(cfg *config.Config, db *sql.DB) *Routes {
	// Create the handler by passing cfg
	h := handler.NewHandler(cfg)
	mw := middleware.NewMiddleware(cfg)
	return &Routes{
		Config:     cfg,
		Handler:    h,
		Middleware: mw,
	}
}

func (r *Routes) Routes() http.Handler {
	mux := chi.NewRouter()

	// Setup global middleware
	r.Middleware.SetupMiddleware(mux)

	// Register public routes
	r.publicRoutes(mux)
	r.Config.Logger.Info("✅ Routes endpoints initialized successfully")

	return mux
}

func (r *Routes) publicRoutes(mux *chi.Mux) {
	mux.Route("/auth", func(mux chi.Router) {
		mux.Get("/health", r.Handler.HealthCheckHandler)
		// Add other /auth related routes here
	})
}
