package models

import (
	"time"
)

// User represents a user in the system.
type User struct {
	ID        int       `json:"id"`
	Username  string    `json:"username"`
	Password  string    `json:"password"` // In a real-world application, this should be hashed and salted.
	CreatedAt time.Time `json:"created_at"`
}

// TextData represents a piece of text data.
type TextData struct {
	ID        int       `json:"id"`
	UserID    int       `json:"user_id"`
	Data      string    `json:"data"`
	Meta      string    `json:"meta"`
	CreatedAt time.Time `json:"created_at"`
}

// BinaryData represents a piece of binary data.
type BinaryData struct {
	ID        int       `json:"id"`
	UserID    int       `json:"user_id"`
	Data      []byte    `json:"data"`
	Meta      string    `json:"meta"`
	CreatedAt time.Time `json:"created_at"`
}

// BankCard represents a bank card.
type BankCard struct {
	ID        int       `json:"id"`
	UserID    int       `json:"user_id"`
	Number    string    `json:"number"`
	Expiry    string    `json:"expiry"`
	CVV       string    `json:"cvv"`
	Meta      string    `json:"meta"`
	CreatedAt time.Time `json:"created_at"`
}
