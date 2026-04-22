package service

import (
	"encoding/base64"
	"testing"
	"time"

	"hydra/internal/protocol"
	"hydra/internal/store/memory"
	storetypes "hydra/internal/store/types"
)

func testEnvelope(now time.Time) protocol.MessageEnvelope {
	return protocol.MessageEnvelope{
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
}

func TestSendMessageSuccess(t *testing.T) {
	store := memory.New()
	now := time.Date(2026, 4, 22, 10, 30, 0, 0, time.UTC)
	_, _ = store.CreateUser(storetypes.User{UserID: "bob"})

	svc := NewMessageService(store)
	svc.SetNowFnForTest(func() time.Time { return now })
	res, err := svc.SendMessage(testEnvelope(now))
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
	env := testEnvelope(now)

	if _, err := svc.SendMessage(env); err != nil {
		t.Fatalf("first send error: %v", err)
	}
	if _, err := svc.SendMessage(env); err == nil {
		t.Fatalf("expected duplicate error")
	}
}

func TestPollAndAckMessages(t *testing.T) {
	store := memory.New()
	now := time.Date(2026, 4, 22, 10, 30, 0, 0, time.UTC)
	_, _ = store.CreateUser(storetypes.User{UserID: "bob"})

	svc := NewMessageService(store)
	svc.SetNowFnForTest(func() time.Time { return now })
	res, err := svc.SendMessage(testEnvelope(now))
	if err != nil {
		t.Fatalf("send error: %v", err)
	}

	msgs, err := svc.PollMessages("bob", 50)
	if err != nil {
		t.Fatalf("poll error: %v", err)
	}
	if len(msgs) != 1 {
		t.Fatalf("expected 1 poll notice, got %d", len(msgs))
	}
	if msgs[0].FromUserID != "alice" {
		t.Fatalf("expected from_user_id alice, got %s", msgs[0].FromUserID)
	}

	ack, err := svc.AckMessages("bob", []string{res.ServerMessageID}, now)
	if err != nil {
		t.Fatalf("ack error: %v", err)
	}
	if ack.AckedCount != 1 {
		t.Fatalf("expected acked_count=1 got=%d", ack.AckedCount)
	}
	if len(ack.Messages) != 1 {
		t.Fatalf("expected 1 acked message payload, got %d", len(ack.Messages))
	}

	msgs, err = svc.PollMessages("bob", 50)
	if err != nil {
		t.Fatalf("poll2 error: %v", err)
	}
	if len(msgs) != 0 {
		t.Fatalf("expected 0 message, got %d", len(msgs))
	}
}
