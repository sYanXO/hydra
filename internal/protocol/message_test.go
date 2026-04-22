package protocol

import (
	"encoding/base64"
	"testing"
)

func TestMessageEnvelopeValidateBasic(t *testing.T) {
	env := MessageEnvelope{
		Version:                  1,
		MessageID:                "11111111-1111-4111-8111-111111111111",
		FromUserID:               "alice",
		ToUserID:                 "bob",
		SenderIdentityKeyEd25519: base64.StdEncoding.EncodeToString([]byte("id-key")),
		SenderDHKeyX25519:        base64.StdEncoding.EncodeToString([]byte("dh-key")),
		Nonce:                    base64.StdEncoding.EncodeToString([]byte("nonce-24-byte-placeholder")),
		Ciphertext:               base64.StdEncoding.EncodeToString([]byte("cipher")),
		SentAt:                   "2026-04-22T10:30:00Z",
		Signature:                base64.StdEncoding.EncodeToString([]byte("sig")),
	}
	if err := env.ValidateBasic(); err != nil {
		t.Fatalf("ValidateBasic error: %v", err)
	}
}

func TestMessageEnvelopeValidateBasicFails(t *testing.T) {
	env := MessageEnvelope{Version: 1, MessageID: "not-a-uuid"}
	if err := env.ValidateBasic(); err == nil {
		t.Fatalf("expected error")
	}
}

func TestMessageEnvelopeValidateBasicRejectsSelfMessage(t *testing.T) {
	env := MessageEnvelope{
		Version:                  1,
		MessageID:                "11111111-1111-4111-8111-111111111111",
		FromUserID:               "alice",
		ToUserID:                 "alice",
		SenderIdentityKeyEd25519: base64.StdEncoding.EncodeToString([]byte("id-key")),
		SenderDHKeyX25519:        base64.StdEncoding.EncodeToString([]byte("dh-key")),
		Nonce:                    base64.StdEncoding.EncodeToString([]byte("nonce-24-byte-placeholder")),
		Ciphertext:               base64.StdEncoding.EncodeToString([]byte("cipher")),
		SentAt:                   "2026-04-22T10:30:00Z",
		Signature:                base64.StdEncoding.EncodeToString([]byte("sig")),
	}
	if err := env.ValidateBasic(); err == nil {
		t.Fatalf("expected self-message rejection")
	}
}
