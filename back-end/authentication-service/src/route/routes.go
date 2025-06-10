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
		mux.Get("/last-user", r.Handler.GetLastUserHandler)
		mux.Get("/get-user-by-mail", r.Handler.GetUserByMailAddressHandler)
		mux.Put("/update-user", r.Handler.UpdateUserHandler)
		mux.Post("/register", r.Handler.RegisterUserHandler)
		mux.Post("/login", r.Handler.LoginUserHandler)
		mux.Post("/logout", r.Handler.LogoutUserHandler)
		mux.Post("/refresh-jwt-token", r.Handler.RefreshTokenHandler)
		mux.Delete("/delete-user", r.Handler.DeleteUserHandler)

	})
}
