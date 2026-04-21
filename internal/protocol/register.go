package protocol

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"
)

const RegisterContext = "pi-chat-register-v1"

var (
	ErrInvalidBase64     = errors.New("invalid_base64")
	ErrInvalidPublicKey  = errors.New("invalid_public_key")
	ErrInvalidSignature  = errors.New("invalid_signature")
	ErrInvalidSignedAt   = errors.New("invalid_signed_at")
	ErrSignedAtSkew      = errors.New("signed_at_out_of_window")
	ErrNonceReuse        = errors.New("nonce_reused")
	ErrUserAlreadyExists = errors.New("user_already_registered")
)

type RegisterRequest struct {
	UserID             string `json:"user_id"`
	IdentityKeyEd25519 string `json:"identity_key_ed25519"`
	DHKeyX25519        string `json:"dh_key_x25519"`
	Nonce              string `json:"nonce"`
	SignedAt           string `json:"signed_at"`
	Signature          string `json:"signature"`
}

func (r RegisterRequest) CanonicalString() string {
	lines := []string{
		RegisterContext,
		"user_id:" + r.UserID,
		"identity_key_ed25519:" + r.IdentityKeyEd25519,
		"dh_key_x25519:" + r.DHKeyX25519,
		"nonce:" + r.Nonce,
		"signed_at:" + r.SignedAt,
	}
	return strings.Join(lines, "\n")
}

func (r RegisterRequest) ParsedSignedAt() (time.Time, error) {
	t, err := time.Parse(time.RFC3339, r.SignedAt)
	if err != nil {
		return time.Time{}, ErrInvalidSignedAt
	}
	return t.UTC(), nil
}

func (r RegisterRequest) ValidateTimeWindow(now time.Time, skew time.Duration) error {
	signedAt, err := r.ParsedSignedAt()
	if err != nil {
		return err
	}
	delta := now.Sub(signedAt)
	if delta < 0 {
		delta = -delta
	}
	if delta > skew {
		return ErrSignedAtSkew
	}
	return nil
}

func (r RegisterRequest) VerifySignature() error {
	pub, err := base64.StdEncoding.DecodeString(r.IdentityKeyEd25519)
	if err != nil {
		return ErrInvalidBase64
	}
	if len(pub) != ed25519.PublicKeySize {
		return ErrInvalidPublicKey
	}
	sig, err := base64.StdEncoding.DecodeString(r.Signature)
	if err != nil {
		return ErrInvalidBase64
	}
	if len(sig) != ed25519.SignatureSize {
		return ErrInvalidSignature
	}
	if _, err := base64.StdEncoding.DecodeString(r.DHKeyX25519); err != nil {
		return ErrInvalidBase64
	}
	if _, err := base64.StdEncoding.DecodeString(r.Nonce); err != nil {
		return ErrInvalidBase64
	}
	msg := []byte(r.CanonicalString())
	if !ed25519.Verify(pub, msg, sig) {
		return ErrInvalidSignature
	}
	return nil
}

func (r RegisterRequest) ValidateRequiredFields() error {
	if strings.TrimSpace(r.UserID) == "" || strings.TrimSpace(r.IdentityKeyEd25519) == "" ||
		strings.TrimSpace(r.DHKeyX25519) == "" || strings.TrimSpace(r.Nonce) == "" ||
		strings.TrimSpace(r.SignedAt) == "" || strings.TrimSpace(r.Signature) == "" {
		return fmt.Errorf("missing_required_fields")
	}
	return nil
}
