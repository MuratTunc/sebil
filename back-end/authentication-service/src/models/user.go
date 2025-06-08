package models

type UserRequest struct {
	Username           string `json:"username"`
	MailAddress        string `json:"mail_address"`
	Password           string `json:"password"`
	PhoneNumber        string `json:"phone_number"`
	LanguagePreference string `json:"language_preference"`
	Role               string `json:"role"` // "Admin", "Sales Representative", "Customer"
}
