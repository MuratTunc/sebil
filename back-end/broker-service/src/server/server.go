package server

import (
	"broker-service/src/config"
	"broker-service/src/route"
	"fmt"
	"net/http"
	"time"
)

// StartServer initializes config and starts the HTTP server with graceful shutdown
func StartServer(cfg *config.Config) {
	// Get the logger from the config
	logger := cfg.Logger

	// Initialize routes
	r := route.NewRoutes(cfg)

	// Set up the HTTP server
	srv := &http.Server{
		Addr:    fmt.Sprintf(":%s", cfg.ServicePort),
		Handler: r.Routes(),
	}

	// Log server initialization success
	logger.Info("✅ HTTP server setup completed successfully")

	// Run server in a goroutine
	go func() {
		logger.Info(fmt.Sprintf("✅ %s is running on port: %s", cfg.ServiceName, cfg.ServicePort))
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			// Log the server start failure and terminate the program
			logger.Fatalf("❌ Server failed to start: %v", err)
		}
	}()

	// Call graceful shutdown
	GracefulShutdown(srv, 5*time.Second, logger)
}
