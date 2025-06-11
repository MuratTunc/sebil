package handler

import (
	"authentication-service/src/config"
	errors "authentication-service/src/error"
	"authentication-service/src/models"
	mailer "authentication-service/src/utils"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
)

type Handler struct {
	App *config.Config
}

// NewHandler creates a new Handler instance
func NewHandler(app *config.Config) *Handler {
	app.Logger.Info("✅ Handler initialized successfully")
	return &Handler{App: app}
}

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

	input, err := parseRegisterRequest(r)
	if err != nil {
		http.Error(w, errors.ErrInvalidRequest, http.StatusBadRequest)
		logger.Error("Failed to decode register request: " + err.Error())
		return
	}

	// 🔠 Normalize email
	input.MailAddress = strings.ToLower(strings.TrimSpace(input.MailAddress))

	// Check if user exists before inserting
	exists, err := checkUserExists(h.App.DB, input.Username, input.MailAddress)
	if err != nil {
		http.Error(w, errors.ErrDatabaseQuery, http.StatusInternalServerError)
		logger.Error("Failed to check existing user: " + err.Error())
		return
	}
	if exists {
		http.Error(w, "Username or email already exists", http.StatusConflict)
		return
	}

	// 🔐 Hash the password before storing it
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(input.Password), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, "Failed to hash password", http.StatusInternalServerError)
		logger.Error("Failed to hash password: " + err.Error())
		return
	}
	input.Password = string(hashedPassword)

	// ✅ Insert the user with hashed password
	if err := insertUser(h.App.DB, input); err != nil {
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

func (h *Handler) LoginUserHandler(w http.ResponseWriter, r *http.Request) {
	startTime := time.Now()
	logger := h.App.Logger

	input, err := parseLoginRequest(r)
	if err != nil {
		http.Error(w, errors.ErrInvalidRequest, http.StatusBadRequest)
		logger.Error("Failed to decode login request: " + err.Error())
		return
	}

	userID, hashedPwd, err := fetchUserCredentials(h.App.DB, input.MailAddress)
	if err != nil {
		handleLoginDBError(err, input.MailAddress, w, logger)
		return
	}

	if !validatePassword(hashedPwd, input.Password) {
		http.Error(w, errors.ErrInvalidRequest, http.StatusUnauthorized)
		return
	}

	tokenString, err := generateJWT(userID, h.App.JWTSecret, h.App.JWTExpiration)
	if err != nil {
		http.Error(w, errors.ErrFailedToGenerateJWT, http.StatusInternalServerError)
		logger.Error("Failed to sign JWT: " + err.Error())
		return
	}

	logger.Info("User logged in successfully in " + time.Since(startTime).String())
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"token": tokenString})
}

func (h *Handler) LogoutUserHandler(w http.ResponseWriter, r *http.Request) {
	startTime := time.Now()
	logger := h.App.Logger

	// Get the token from Authorization header (Bearer token)
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		http.Error(w, errors.ErrAuthorizationHeader, http.StatusUnauthorized)
		logger.Error("Logout failed: missing Authorization header")
		return
	}

	var tokenStr string
	fmt.Sscanf(authHeader, "Bearer %s", &tokenStr)
	if tokenStr == "" {
		http.Error(w, errors.ErrAuthorizationInvalid, http.StatusUnauthorized)
		logger.Error("Logout failed: invalid Authorization header format")
		return
	}

	// Parse the token to get userID (implement parseUserIDFromJWT with your JWT lib)
	userID, err := parseUserIDFromJWT(tokenStr, h.App.JWTSecret)
	if err != nil {
		http.Error(w, errors.ErrInvalidJWT, http.StatusUnauthorized)
		logger.Error("Logout failed: invalid token - " + err.Error())
		return
	}

	// Update login_status to false
	err = updateLoginStatus(h.App.DB, userID, false)
	if err != nil {
		http.Error(w, errors.ErrFailedToLogout, http.StatusInternalServerError)
		logger.Error("Logout DB update failed: " + err.Error())
		return
	}

	logger.Info("User logged out successfully in " + time.Since(startTime).String())
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"message": "Logout successful"})
}

func (h *Handler) RefreshTokenHandler(w http.ResponseWriter, r *http.Request) {
	startTime := time.Now()
	logger := h.App.Logger

	// Get the token from Authorization header
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		http.Error(w, errors.ErrTokenMissing, http.StatusUnauthorized)
		return
	}

	parts := strings.SplitN(authHeader, " ", 2)
	if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
		http.Error(w, errors.ErrTokenInvalid, http.StatusUnauthorized)
		return
	}
	tokenString := parts[1]

	// Parse and validate token
	userIDStr, err := parseUserIDFromJWT(tokenString, h.App.JWTSecret)
	if err != nil {
		http.Error(w, errors.ErrTokenInvalid, http.StatusUnauthorized)
		logger.Error("Failed to parse token in refresh: " + err.Error())
		return
	}

	userID, err := strconv.Atoi(userIDStr)
	if err != nil {
		http.Error(w, "Invalid user ID in token", http.StatusUnauthorized)
		logger.Error("User ID conversion error: " + err.Error())
		return
	}

	// Generate new token with fresh expiry
	newToken, err := generateJWT(userID, h.App.JWTSecret, h.App.JWTExpiration)
	if err != nil {
		http.Error(w, errors.ErrTokenFailure, http.StatusInternalServerError)
		logger.Error("Failed to generate new JWT token: " + err.Error())
		return
	}

	logger.Info("Token refreshed successfully in " + time.Since(startTime).String())

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"token": newToken})
}

func (h *Handler) GetUserByMailAddressHandler(w http.ResponseWriter, r *http.Request) {
	startTime := time.Now()
	logger := h.App.Logger

	// Get mail address from query parameters
	mail := r.URL.Query().Get("mail_address")
	if mail == "" {
		http.Error(w, "Missing mail_address query parameter", http.StatusBadRequest)
		return
	}

	query := `SELECT id, username, mail_address, role, activated, created_at FROM users WHERE mail_address = $1 LIMIT 1`
	row := h.App.DB.QueryRow(query, mail)

	var user models.User
	err := row.Scan(&user.ID, &user.Username, &user.MailAddress, &user.Role, &user.Activated, &user.CreatedAt)
	if err != nil {
		logger.Error("User not found: " + err.Error())
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(user); err != nil {
		logger.Error("Failed to encode user response: " + err.Error())
	}

	logger.Info("User fetched by mail_address successfully in " + time.Since(startTime).String())
}

func (h *Handler) UpdateUserHandler(w http.ResponseWriter, r *http.Request) {
	startTime := time.Now()
	logger := h.App.Logger

	var req models.UpdateUserRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		logger.Error("Failed to decode request body: " + err.Error())
		http.Error(w, "Invalid request payload", http.StatusBadRequest)
		return
	}

	if req.MailAddress == "" {
		http.Error(w, "mail_address is required", http.StatusBadRequest)
		return
	}

	queryResult := BuildUpdateUserQuery(req.Username, req.Role, req.Activated, req.MailAddress)
	if queryResult.HasError {
		http.Error(w, queryResult.ErrorMsg, http.StatusBadRequest)
		return
	}

	result, err := h.App.DB.Exec(queryResult.Query, queryResult.Args...)
	if err != nil {
		logger.Error("Failed to execute update: " + err.Error())
		http.Error(w, "Failed to update user", http.StatusInternalServerError)
		return
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		http.Error(w, "No user found with the given mail address", http.StatusNotFound)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("User updated successfully"))
	logger.Info("User updated successfully in " + time.Since(startTime).String())
}

func (h *Handler) DeleteUserHandler(w http.ResponseWriter, r *http.Request) {
	startTime := time.Now()
	logger := h.App.Logger

	var req models.DeleteRequest

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		logger.Error("Failed to decode delete user request: " + err.Error())
		http.Error(w, "Invalid request payload", http.StatusBadRequest)
		return
	}

	if req.MailAddress == "" {
		http.Error(w, "Missing mail_address", http.StatusBadRequest)
		return
	}

	query := `DELETE FROM users WHERE mail_address = $1`
	res, err := h.App.DB.Exec(query, req.MailAddress)
	if err != nil {
		logger.Error("Failed to delete user: " + err.Error())
		http.Error(w, "Failed to delete user", http.StatusInternalServerError)
		return
	}

	rowsAffected, err := res.RowsAffected()
	if err != nil {
		logger.Error("Failed to get rows affected: " + err.Error())
		http.Error(w, "Error checking deletion result", http.StatusInternalServerError)
		return
	}

	if rowsAffected == 0 {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	logger.Info("User deleted successfully in " + time.Since(startTime).String())
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("User deleted successfully"))
}

func (h *Handler) ChangePasswordHandler(w http.ResponseWriter, r *http.Request) {
	startTime := time.Now()
	logger := h.App.Logger

	var req models.ChangePasswordRequest

	// Parse request body
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request payload", http.StatusBadRequest)
		logger.Error("Failed to decode change password request: " + err.Error())
		return
	}

	req.MailAddress = strings.ToLower(req.MailAddress)

	// Get existing hashed password from DB
	var hashedPassword string
	query := `SELECT password FROM users WHERE mail_address = $1`
	err := h.App.DB.QueryRow(query, req.MailAddress).Scan(&hashedPassword)
	if err != nil {
		if err == sql.ErrNoRows {
			http.Error(w, "User not found", http.StatusNotFound)
		} else {
			http.Error(w, "Database error", http.StatusInternalServerError)
		}
		logger.Error("Failed to fetch user for password change: " + err.Error())
		return
	}

	// Verify old password
	if err := bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(req.OldPassword)); err != nil {
		http.Error(w, "Old password is incorrect", http.StatusUnauthorized)
		logger.Warn("Incorrect old password attempt for " + req.MailAddress)
		return
	}

	// Hash the new password
	newHashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.NewPassword), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, "Failed to hash new password", http.StatusInternalServerError)
		logger.Error("Failed to hash new password: " + err.Error())
		return
	}

	// Update password in DB
	updateQuery := `UPDATE users SET password = $1, updated_at = CURRENT_TIMESTAMP WHERE mail_address = $2`
	_, err = h.App.DB.Exec(updateQuery, newHashedPassword, req.MailAddress)
	if err != nil {
		http.Error(w, "Failed to update password", http.StatusInternalServerError)
		logger.Error("Failed to update password in DB: " + err.Error())
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Password changed successfully"))
	logger.Info("Password updated successfully for " + req.MailAddress + " in " + time.Since(startTime).String())
}

func (h *Handler) ForgotPasswordHandler(w http.ResponseWriter, r *http.Request) {
	startTime := time.Now()
	logger := h.App.Logger

	var req models.ForgotPasswordRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request payload", http.StatusBadRequest)
		logger.Error("Failed to decode forgot password request: " + err.Error())
		return
	}

	req.MailAddress = strings.ToLower(strings.TrimSpace(req.MailAddress))
	if !strings.Contains(req.MailAddress, "@") {
		http.Error(w, "Invalid email format", http.StatusBadRequest)
		return
	}

	var userID int
	err := h.App.DB.QueryRow(`SELECT id FROM users WHERE mail_address = $1`, req.MailAddress).Scan(&userID)

	if err == sql.ErrNoRows {
		// User not found, respond with generic success message (no info leak)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("If the email exists, a reset link/code has been sent."))
		logger.Info("Forgot password requested for non-existing email: " + req.MailAddress)
		return
	}

	if err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		logger.Error("Database query failed: " + err.Error())
		return
	}

	// User found, generate reset code and update DB
	resetCode, err := generateResetCode()
	if err != nil {
		logger.Error("Error generating reset code: " + err.Error())
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	err = h.UpdateResetCode(req.MailAddress, resetCode)
	if err != nil {
		logger.Error("Failed to update reset code: " + err.Error())
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	go func() {
		err := mailer.SendPasswordResetMail(req.MailAddress, resetCode, h.App)
		if err != nil {
			logger.Error("Failed to send password reset email to: " + req.MailAddress + " " + err.Error())
		} else {
			logger.Info("Password reset email sent to " + req.MailAddress)
		}
	}()

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("If the email exists, a reset link/code has been sent."))
	logger.Info("Forgot password process completed in " + time.Since(startTime).String())
}
