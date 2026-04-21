package service

import (
	"encoding/base64"
	"testing"
	"time"

	"hydra/internal/protocol"
	"hydra/internal/store/memory"
	storetypes "hydra/internal/store/types"
)

func TestSendMessageSuccess(t *testing.T) {
	store := memory.New()
	now := time.Date(2026, 4, 22, 10, 30, 0, 0, time.UTC)
	_, _ = store.CreateUser(storetypes.User{UserID: "bob"})

	svc := NewMessageService(store)
	svc.SetNowFnForTest(func() time.Time { return now })
	env := protocol.MessageEnvelope{
		Version:                  1,
		MessageID:                "11111111-1111-4111-8111-111111111111",
		FromUserID:               "alice",
		ToUserID:                 "bob",
		SenderIdentityKeyEd25519: base64.StdEncoding.EncodeToString([]byte("id-key")),
		SenderDHKeyX25519:        base64.StdEncoding.EncodeToString([]byte("dh-key")),
		Nonce:                    base64.StdEncoding.EncodeToString([]byte("nonce-24-byte-placeholder")),
		Ciphertext:               base64.StdEncoding.EncodeToString([]byte("cipher")),
		SentAt:                   now.Format(time.RFC3339),
		Signature:                base64.StdEncoding.EncodeToString([]byte("sig")),
	}

	res, err := svc.SendMessage(env)
	if err != nil {
		t.Fatalf("SendMessage error: %v", err)
	}
	if res.ServerMessageID == "" {
		t.Fatalf("expected server_message_id")
	}
}

func TestSendMessageDuplicate(t *testing.T) {
	store := memory.New()
	now := time.Date(2026, 4, 22, 10, 30, 0, 0, time.UTC)
	_, _ = store.CreateUser(storetypes.User{UserID: "bob"})

	svc := NewMessageService(store)
	svc.SetNowFnForTest(func() time.Time { return now })
	env := protocol.MessageEnvelope{
		Version:                  1,
		MessageID:                "11111111-1111-4111-8111-111111111111",
		FromUserID:               "alice",
		ToUserID:                 "bob",
		SenderIdentityKeyEd25519: base64.StdEncoding.EncodeToString([]byte("id-key")),
		SenderDHKeyX25519:        base64.StdEncoding.EncodeToString([]byte("dh-key")),
		Nonce:                    base64.StdEncoding.EncodeToString([]byte("nonce-24-byte-placeholder")),
		Ciphertext:               base64.StdEncoding.EncodeToString([]byte("cipher")),
		SentAt:                   now.Format(time.RFC3339),
		Signature:                base64.StdEncoding.EncodeToString([]byte("sig")),
	}

	if _, err := svc.SendMessage(env); err != nil {
		t.Fatalf("first send error: %v", err)
	}
	if _, err := svc.SendMessage(env); err == nil {
		t.Fatalf("expected duplicate error")
	}
}
