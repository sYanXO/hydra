package types

import "time"

type User struct {
	UserID             string
	IdentityKeyEd25519 string
	DHKeyX25519        string
	CreatedAt          time.Time
	UpdatedAt          time.Time
}
