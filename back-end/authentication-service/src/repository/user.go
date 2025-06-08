package repository

import (
	"authentication-service/src/models"
	"database/sql"
)

func InsertUser(db *sql.DB, user models.UserRequest) error {
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

func CheckUserExists(db *sql.DB, username, mailAddress string) (bool, error) {
	var exists bool
	query := `SELECT EXISTS(SELECT 1 FROM users WHERE username=$1 OR mail_address=$2)`
	err := db.QueryRow(query, username, mailAddress).Scan(&exists)
	return exists, err
}
