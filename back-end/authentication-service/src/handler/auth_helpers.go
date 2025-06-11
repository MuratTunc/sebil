package handler

import (
	"authentication-service/src/logger"
	"authentication-service/src/models"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"errors"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

type UpdateQueryResult struct {
	Query    string
	Args     []interface{}
	HasError bool
	ErrorMsg string
}

func BuildUpdateUserQuery(reqUsername, reqRole string, reqActivated *bool, mailAddress string) UpdateQueryResult {
	query := `UPDATE users SET `
	args := []interface{}{}
	paramIdx := 1

	if reqUsername != "" {
		query += fmt.Sprintf("username = $%d,", paramIdx)
		args = append(args, reqUsername)
		paramIdx++
	}

	if reqRole != "" {
		query += fmt.Sprintf("role = $%d,", paramIdx)
		args = append(args, reqRole)
		paramIdx++
	}

	if reqActivated != nil {
		query += fmt.Sprintf("activated = $%d,", paramIdx)
		args = append(args, *reqActivated)
		paramIdx++
	}

	if len(args) == 0 {
		return UpdateQueryResult{
			HasError: true,
			ErrorMsg: "No fields to update",
		}
	}

	query = strings.TrimSuffix(query, ",")
	query += fmt.Sprintf(" WHERE mail_address = $%d", paramIdx)
	args = append(args, mailAddress)

	return UpdateQueryResult{
		Query: query,
		Args:  args,
	}
}

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

// Helper function to update login_status in DB
func updateLoginStatus(db *sql.DB, userID string, status bool) error {
	_, err := db.Exec("UPDATE users SET login_status = $1, updated_at = CURRENT_TIMESTAMP WHERE id = $2", status, userID)
	return err
}

func parseRegisterRequest(r *http.Request) (models.UserRequest, error) {
	var input models.UserRequest
	err := json.NewDecoder(r.Body).Decode(&input)
	return input, err
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
		http.Error(w, "Database error for email ", http.StatusInternalServerError)
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
		"jti":     uuid.New().String(), // adds uniqueness
	})
	return token.SignedString([]byte(secret))
}

// parseUserIDFromJWT parses the JWT token string using the secret and returns the userID as a string.
func parseUserIDFromJWT(tokenStr, secret string) (string, error) {
	// Define a custom claims struct or use jwt.MapClaims if you want flexibility
	claims := jwt.MapClaims{}

	// Parse token
	token, err := jwt.ParseWithClaims(tokenStr, claims, func(token *jwt.Token) (interface{}, error) {
		// Make sure signing method is HMAC
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("jwt:unexpected signing method")
		}
		return []byte(secret), nil
	})

	if err != nil {
		return "", err
	}

	if !token.Valid {
		return "", errors.New("jwt:invalid JWTtoken")
	}

	// Extract userID from claims
	userIDRaw, ok := claims["user_id"]
	if !ok {
		return "", errors.New("jwt:user_id claim missing in token")
	}

	userID, ok := userIDRaw.(string)
	if !ok {
		// Sometimes userID could be float64 if encoded as number, so handle that
		switch v := userIDRaw.(type) {
		case float64:
			userID = fmt.Sprintf("%.0f", v)
		default:
			return "", errors.New("jwt:user_id claim is not a string")
		}
	}

	return userID, nil
}

func generateResetCode() (string, error) {
	const digits = "0123456789"
	const length = 6
	b := make([]byte, length)
	_, err := rand.Read(b)
	if err != nil {
		return "", errors.New("failed to generate reset code: " + err.Error())
	}

	for i := 0; i < length; i++ {
		b[i] = digits[int(b[i])%len(digits)]
	}

	return string(b), nil
}

func (h *Handler) UpdateResetCode(mail string, resetcode string) error {
	query := `UPDATE users SET resetcode = $1, updated_at = NOW() WHERE mail_address = $2`
	res, err := h.App.DB.Exec(query, resetcode, mail)
	if err != nil {
		return err
	}
	rowsAffected, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if rowsAffected == 0 {
		return fmt.Errorf("no user found with mail_address %s", mail)
	}
	return nil
}
