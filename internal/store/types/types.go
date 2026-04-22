package types

import "time"

type User struct {
	UserID             string
	IdentityKeyEd25519 string
	DHKeyX25519        string
	CreatedAt          time.Time
	UpdatedAt          time.Time
}

type UserHandle struct {
	UserID        string
	UsernameNorm  string
	Discriminator string
	Active        bool
	CreatedAt     time.Time
	DeactivatedAt *time.Time
}

type Message struct {
	ServerMessageID string
	ToUserID        string
	FromUserID      string
	MessageID       string
	EnvelopeJSON    []byte
	Status          string
	ReceivedAt      time.Time
	DeliveredAt     *time.Time
	ExpiresAt       time.Time
}
