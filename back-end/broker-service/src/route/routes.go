package route

import (
	"broker-service/src/config"
	"broker-service/src/handler"
	"broker-service/src/middleware"
	"net/http"

	"github.com/go-chi/chi/v5"
)

type Routes struct {
	Config     *config.Config
	Handler    *handler.Handler
	Middleware *middleware.Middleware
}

func NewRoutes(cfg *config.Config) *Routes {
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
	mux.Route("/broker", func(mux chi.Router) {
		mux.Get("/health", r.Handler.HealthCheckHandler)
		// future endpoints here...
	})
}
