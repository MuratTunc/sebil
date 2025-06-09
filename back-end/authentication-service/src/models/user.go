package models

import "time"

type UserRequest struct {
	Username           string `json:"username"`
	MailAddress        string `json:"mail_address"`
	Password           string `json:"password"`
	PhoneNumber        string `json:"phone_number"`
	LanguagePreference string `json:"language_preference"`
	Role               string `json:"role"` // "Admin", "Sales Representative", "Customer"
}

type User struct {
	ID          int       `json:"id"`
	Username    string    `json:"username"`
	MailAddress string    `json:"mail_address"`
	Role        string    `json:"role"`
	Activated   bool      `json:"activated"`
	CreatedAt   time.Time `json:"created_at"`
}
