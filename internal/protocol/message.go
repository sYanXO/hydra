package protocol

import (
	"encoding/base64"
	"errors"
	"regexp"
	"strings"
	"time"
)

var (
	ErrInvalidEnvelope   = errors.New("invalid_envelope")
	ErrRecipientNotFound = errors.New("recipient_not_found")
	ErrDuplicateMessage  = errors.New("duplicate_message_id")

	uuidV4Like = regexp.MustCompile(`^[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[1-5][a-fA-F0-9]{3}-[89abAB][a-fA-F0-9]{3}-[a-fA-F0-9]{12}$`)
)

type MessageEnvelope struct {
	Version                  int    `json:"version"`
	MessageID                string `json:"message_id"`
	FromUserID               string `json:"from_user_id"`
	ToUserID                 string `json:"to_user_id"`
	SenderIdentityKeyEd25519 string `json:"sender_identity_key_ed25519"`
	SenderDHKeyX25519        string `json:"sender_dh_key_x25519"`
	Nonce                    string `json:"nonce"`
	Ciphertext               string `json:"ciphertext"`
	SentAt                   string `json:"sent_at"`
	Signature                string `json:"signature"`
}

func (m MessageEnvelope) ValidateBasic() error {
	if m.Version != 1 {
		return ErrInvalidEnvelope
	}
	if strings.TrimSpace(m.MessageID) == "" || strings.TrimSpace(m.FromUserID) == "" ||
		!uuidV4Like.MatchString(m.MessageID) ||
		strings.TrimSpace(m.ToUserID) == "" || strings.TrimSpace(m.SenderIdentityKeyEd25519) == "" ||
		strings.TrimSpace(m.SenderDHKeyX25519) == "" || strings.TrimSpace(m.Nonce) == "" ||
		strings.TrimSpace(m.Ciphertext) == "" || strings.TrimSpace(m.SentAt) == "" ||
		strings.TrimSpace(m.Signature) == "" {
		return ErrInvalidEnvelope
	}
	if _, err := base64.StdEncoding.DecodeString(m.SenderIdentityKeyEd25519); err != nil {
		return ErrInvalidEnvelope
	}
	if _, err := base64.StdEncoding.DecodeString(m.SenderDHKeyX25519); err != nil {
		return ErrInvalidEnvelope
	}
	if _, err := base64.StdEncoding.DecodeString(m.Nonce); err != nil {
		return ErrInvalidEnvelope
	}
	if _, err := base64.StdEncoding.DecodeString(m.Ciphertext); err != nil {
		return ErrInvalidEnvelope
	}
	if _, err := base64.StdEncoding.DecodeString(m.Signature); err != nil {
		return ErrInvalidEnvelope
	}
	if _, err := time.Parse(time.RFC3339, m.SentAt); err != nil {
		return ErrInvalidEnvelope
	}
	return nil
}
