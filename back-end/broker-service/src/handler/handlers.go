package handler

import (
	"broker-service/src/config"
	errors "broker-service/src/error"
	"net/http"
	"time"
)

type Handler struct {
	App *config.Config
}

// NewHandler creates a new Handler instance
func NewHandler(app *config.Config) *Handler {
	app.Logger.Info("✅ Handler initialized successfully")
	return &Handler{App: app}
}

// HealthCheckHandler handles the health check endpoint
func (h *Handler) HealthCheckHandler(w http.ResponseWriter, r *http.Request) {

	startTime := time.Now() // Start the timer for request processing duration
	logger := h.App.Logger

	errorOccurred := false // Change this to simulate an error

	if errorOccurred {
		http.Error(w, errors.ErrInternalServer, http.StatusInternalServerError) // Using the error constant
		logger.Error(errors.ErrInternalServer)
		return
	}

	// If everything is fine, return success
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Broker Service is up!"))

	// Calculate the time taken for the request to be processed
	duration := time.Since(startTime)

	// Log the success after the HTTP response
	logger.Info("HealthCheck passed Duration: " + duration.String())
}
