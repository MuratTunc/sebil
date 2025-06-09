package handler

import (
	"authentication-service/src/config"
	errors "authentication-service/src/error"
	"authentication-service/src/models"
	"authentication-service/src/repository"
	"encoding/json"
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
	w.Write([]byte("Authentication Service is up!"))

	// Calculate the time taken for the request to be processed
	duration := time.Since(startTime)

	// Log the success after the HTTP response
	logger.Info("HealthCheck passed Duration: " + duration.String())
}

func (h *Handler) RegisterUserHandler(w http.ResponseWriter, r *http.Request) {
	startTime := time.Now()
	logger := h.App.Logger
	var input models.UserRequest

	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		http.Error(w, errors.ErrInvalidRequest, http.StatusBadRequest)
		logger.Error("Failed to decode user input: " + err.Error())
		return
	}

	// Check if user exists before insert
	exists, err := repository.CheckUserExists(h.App.DB, input.Username, input.MailAddress)
	if err != nil {
		http.Error(w, errors.ErrDatabaseQuery, http.StatusInternalServerError)
		logger.Error("Failed to check existing user: " + err.Error())
		return
	}
	if exists {
		http.Error(w, "Username or email already exists", http.StatusConflict)
		return
	}

	if err := repository.InsertUser(h.App.DB, input); err != nil {
		http.Error(w, errors.ErrDatabaseInsert, http.StatusInternalServerError)
		logger.Error("Failed to insert user: " + err.Error())
		return
	}

	w.WriteHeader(http.StatusCreated)
	w.Write([]byte("User registered successfully"))

	logger.Info("User registered successfully in " + time.Since(startTime).String())
}

func (h *Handler) GetLastUserHandler(w http.ResponseWriter, r *http.Request) {
	startTime := time.Now()
	logger := h.App.Logger

	query := `SELECT id, username, mail_address, role, activated, created_at FROM users ORDER BY created_at DESC LIMIT 1`

	row := h.App.DB.QueryRow(query)

	var user models.User

	err := row.Scan(&user.ID, &user.Username, &user.MailAddress, &user.Role, &user.Activated, &user.CreatedAt)
	if err != nil {
		logger.Error("Failed to fetch last user: " + err.Error())
		http.Error(w, "Failed to retrieve last user", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(user); err != nil {
		logger.Error("Failed to encode user response: " + err.Error())
	}

	logger.Info("Last user fetched successfully in " + time.Since(startTime).String())
}

func (h *Handler) DeleteUserHandler(w http.ResponseWriter, r *http.Request) {
	startTime := time.Now()
	logger := h.App.Logger

	username := r.URL.Query().Get("username")
	if username == "" {
		http.Error(w, "Missing 'username' query parameter", http.StatusBadRequest)
		return
	}

	query := `DELETE FROM users WHERE username = $1`
	result, err := h.App.DB.Exec(query, username)
	if err != nil {
		logger.Error("Failed to delete user: " + err.Error())
		http.Error(w, "Failed to delete user", http.StatusInternalServerError)
		return
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		logger.Error("Failed to get rows affected: " + err.Error())
		http.Error(w, "Could not confirm deletion", http.StatusInternalServerError)
		return
	}

	if rowsAffected == 0 {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("User deleted successfully"))

	logger.Info("User '" + username + "' deleted successfully in " + time.Since(startTime).String())
}
