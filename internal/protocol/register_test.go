package protocol

import (
	"crypto/ed25519"
	"encoding/base64"
	"testing"
	"time"
)

func makeSignedRequest(t *testing.T) RegisterRequest {
	t.Helper()
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i + 1)
	}
	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)

	req := RegisterRequest{
		UserID:             "11111111-1111-1111-1111-111111111111",
		IdentityKeyEd25519: base64.StdEncoding.EncodeToString(pub),
		DHKeyX25519:        base64.StdEncoding.EncodeToString([]byte("dummy-x25519-public-key-32bytes!!!")),
		Nonce:              base64.StdEncoding.EncodeToString([]byte("0123456789abcdef")),
		SignedAt:           "2026-04-22T10:30:00Z",
	}
	sig := ed25519.Sign(priv, []byte(req.CanonicalString()))
	req.Signature = base64.StdEncoding.EncodeToString(sig)
	return req
}

func TestCanonicalStringStable(t *testing.T) {
	req := RegisterRequest{
		UserID:             "u1",
		IdentityKeyEd25519: "idKey",
		DHKeyX25519:        "dhKey",
		Nonce:              "nonce",
		SignedAt:           "2026-04-22T10:30:00Z",
	}
	got := req.CanonicalString()
	want := "pi-chat-register-v1\n" +
		"user_id:u1\n" +
		"identity_key_ed25519:idKey\n" +
		"dh_key_x25519:dhKey\n" +
		"nonce:nonce\n" +
		"signed_at:2026-04-22T10:30:00Z"
	if got != want {
		t.Fatalf("canonical mismatch\nwant: %q\n got: %q", want, got)
	}
}

func TestVerifySignatureOK(t *testing.T) {
	req := makeSignedRequest(t)
	if err := req.VerifySignature(); err != nil {
		t.Fatalf("VerifySignature() error = %v", err)
	}
}

func TestVerifySignatureTamperFails(t *testing.T) {
	req := makeSignedRequest(t)
	req.Nonce = base64.StdEncoding.EncodeToString([]byte("changednonce12345"))
	if err := req.VerifySignature(); err == nil {
		t.Fatalf("expected signature verification failure")
	}
}

func TestValidateTimeWindow(t *testing.T) {
	req := makeSignedRequest(t)
	now := time.Date(2026, 4, 22, 10, 34, 0, 0, time.UTC)
	if err := req.ValidateTimeWindow(now, 5*time.Minute); err != nil {
		t.Fatalf("expected valid window, got %v", err)
	}

	now = time.Date(2026, 4, 22, 10, 36, 0, 0, time.UTC)
	if err := req.ValidateTimeWindow(now, 5*time.Minute); err == nil {
		t.Fatalf("expected window skew error")
	}
}
