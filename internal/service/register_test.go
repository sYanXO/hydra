package service

import (
	"crypto/ed25519"
	"encoding/base64"
	"testing"
	"time"

	"hydra/internal/protocol"
	"hydra/internal/store/memory"
)

func signedReq(t *testing.T, nonce string, signedAt time.Time) protocol.RegisterRequest {
	t.Helper()
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i + 7)
	}
	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)
	req := protocol.RegisterRequest{
		UserID:             "22222222-2222-2222-2222-222222222222",
		IdentityKeyEd25519: base64.StdEncoding.EncodeToString(pub),
		DHKeyX25519:        base64.StdEncoding.EncodeToString([]byte("dh-key-32-byte-placeholder-value!!")),
		Nonce:              nonce,
		SignedAt:           signedAt.UTC().Format(time.RFC3339),
	}
	req.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(priv, []byte(req.CanonicalString())))
	return req
}

func TestRegisterSuccess(t *testing.T) {
	store := memory.New()
	svc := NewRegisterService(store)
	now := time.Date(2026, 4, 22, 10, 30, 0, 0, time.UTC)
	svc.SetNowFnForTest(func() time.Time { return now })

	req := signedReq(t, base64.StdEncoding.EncodeToString([]byte("nonce-12345678901")), now)
	res, err := svc.Register(req)
	if err != nil {
		t.Fatalf("Register() error = %v", err)
	}
	if res.UserID != req.UserID {
		t.Fatalf("unexpected user id: got %s want %s", res.UserID, req.UserID)
	}
	if res.Handle.Full() == "" {
		t.Fatalf("expected generated handle")
	}
}

func TestRegisterRejectsReplayNonce(t *testing.T) {
	store := memory.New()
	svc := NewRegisterService(store)
	now := time.Date(2026, 4, 22, 10, 30, 0, 0, time.UTC)
	svc.SetNowFnForTest(func() time.Time { return now })

	nonce := base64.StdEncoding.EncodeToString([]byte("nonce-12345678901"))
	first := signedReq(t, nonce, now)
	if _, err := svc.Register(first); err != nil {
		t.Fatalf("first register unexpected error: %v", err)
	}

	second := signedReq(t, nonce, now)
	second.UserID = "33333333-3333-3333-3333-333333333333"
	second.Signature = ""
	// resign for changed user id
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i + 7)
	}
	priv := ed25519.NewKeyFromSeed(seed)
	second.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(priv, []byte(second.CanonicalString())))

	if _, err := svc.Register(second); err != nil {
		t.Fatalf("expected success for different user with same nonce; got %v", err)
	}

	third := signedReq(t, nonce, now)
	if _, err := svc.Register(third); err == nil {
		t.Fatalf("expected nonce replay error for same user")
	}
}

func TestRegisterRejectsSignedAtSkew(t *testing.T) {
	store := memory.New()
	svc := NewRegisterService(store)
	now := time.Date(2026, 4, 22, 10, 30, 0, 0, time.UTC)
	svc.SetNowFnForTest(func() time.Time { return now })

	req := signedReq(t, base64.StdEncoding.EncodeToString([]byte("nonce-12345678901")), now.Add(-6*time.Minute))
	if _, err := svc.Register(req); err == nil {
		t.Fatalf("expected signed_at skew error")
	}
}

func TestGetUserKeys(t *testing.T) {
	store := memory.New()
	svc := NewRegisterService(store)
	now := time.Date(2026, 4, 22, 10, 30, 0, 0, time.UTC)
	svc.SetNowFnForTest(func() time.Time { return now })

	req := signedReq(t, base64.StdEncoding.EncodeToString([]byte("nonce-abcdef123456")), now)
	if _, err := svc.Register(req); err != nil {
		t.Fatalf("register error: %v", err)
	}

	keys, err := svc.GetUserKeys(req.UserID)
	if err != nil {
		t.Fatalf("GetUserKeys error: %v", err)
	}
	if keys.UserID != req.UserID || keys.KeysetVersion != 1 {
		t.Fatalf("unexpected keys result: %+v", keys)
	}
	if keys.Handle.Full() == "" {
		t.Fatalf("expected handle in keys result")
	}

	keysByHandle, err := svc.GetUserKeysByHandle(keys.Handle.UsernameNorm, keys.Handle.Discriminator)
	if err != nil {
		t.Fatalf("GetUserKeysByHandle error: %v", err)
	}
	if keysByHandle.UserID != req.UserID {
		t.Fatalf("unexpected user id from handle lookup: %+v", keysByHandle)
	}
}
