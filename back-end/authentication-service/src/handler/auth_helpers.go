package handler

import (
	errors "authentication-service/src/error"
	"authentication-service/src/logger"
	"authentication-service/src/models"
	"database/sql"
	"encoding/json"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

func checkUserExists(db *sql.DB, username, mailAddress string) (bool, error) {
	var exists bool
	query := `SELECT EXISTS(SELECT 1 FROM users WHERE username=$1 OR mail_address=$2)`
	err := db.QueryRow(query, username, mailAddress).Scan(&exists)
	return exists, err
}

func insertUser(db *sql.DB, user models.UserRequest) error {
	query := `
		INSERT INTO users (
			username, mail_address, password, role, phone_number, language_preference,
			activated, login_status, created_at, updated_at
		) VALUES (
			$1, $2, $3, $4, $5, $6,
			false, false, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP
		)
	`
	_, err := db.Exec(query,
		user.Username,
		user.MailAddress,
		user.Password,
		user.Role,
		user.PhoneNumber,
		user.LanguagePreference,
	)
	return err
}

func parseLoginRequest(r *http.Request) (models.LoginRequest, error) {
	var input models.LoginRequest
	err := json.NewDecoder(r.Body).Decode(&input)
	return input, err
}

func fetchUserCredentials(db *sql.DB, email string) (int, string, error) {
	var userID int
	var hashedPwd string
	query := `SELECT id, password FROM users WHERE mail_address = $1`
	err := db.QueryRow(query, email).Scan(&userID, &hashedPwd)
	return userID, hashedPwd, err
}

func handleLoginDBError(err error, email string, w http.ResponseWriter, logger *logger.Logger) {
	if err == sql.ErrNoRows {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		logger.Warn("Login attempt failed: user not found with email " + email)
	} else {
		http.Error(w, errors.ErrDatabaseQuery, http.StatusInternalServerError)
		logger.Error("Database error for email " + email + ": " + err.Error())
	}
}

func validatePassword(hashedPwd, plainPwd string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hashedPwd), []byte(plainPwd))
	return err == nil
}

func generateJWT(userID int, secret string, expiration time.Duration) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user_id": userID,
		"exp":     time.Now().Add(expiration).Unix(),
	})
	return token.SignedString([]byte(secret))
}
