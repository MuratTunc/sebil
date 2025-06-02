package models

import "time"

// RequestLog will store information about each request processed by broker-service.
type RequestLog struct {
	ID          uint      `gorm:"primaryKey"`
	RequestID   string    `gorm:"unique;not null"`   // Unique ID for tracking
	RequestType string    `gorm:"not null"`          // Type of the request (GET, POST, etc.)
	Timestamp   time.Time `gorm:"not null"`          // When the request was processed
	Status      string    `gorm:"default:'pending'"` // Optional status (e.g., 'pending', 'success', 'failure')
}
