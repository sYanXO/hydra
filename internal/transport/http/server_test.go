package httptransport

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"hydra/internal/protocol"
	"hydra/internal/service"
	"hydra/internal/store/memory"
)

func makeRegisterJSON(t *testing.T, userID string, now time.Time) []byte {
	t.Helper()
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i + 11)
	}
	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)
	req := protocol.RegisterRequest{
		UserID:             userID,
		IdentityKeyEd25519: base64.StdEncoding.EncodeToString(pub),
		DHKeyX25519:        base64.StdEncoding.EncodeToString([]byte("wsX25519PublicValuePlaceholder001")),
		Nonce:              base64.StdEncoding.EncodeToString([]byte("nonce-12345678901")),
		SignedAt:           now.UTC().Format(time.RFC3339),
	}
	req.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(priv, []byte(req.CanonicalString())))
	b, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func makeMessageJSON(toUserID string) []byte {
	req := protocol.MessageEnvelope{
		Version:                  1,
		MessageID:                "11111111-1111-4111-8111-111111111111",
		FromUserID:               "alice-uuid",
		ToUserID:                 toUserID,
		SenderIdentityKeyEd25519: base64.StdEncoding.EncodeToString([]byte("identity-public-key")),
		SenderDHKeyX25519:        base64.StdEncoding.EncodeToString([]byte("dh-public-key")),
		Nonce:                    base64.StdEncoding.EncodeToString([]byte("nonce-24-byte-placeholder")),
		Ciphertext:               base64.StdEncoding.EncodeToString([]byte("ciphertext-bytes")),
		SentAt:                   "2026-04-22T10:30:00Z",
		Signature:                base64.StdEncoding.EncodeToString([]byte("signature-bytes")),
	}
	b, _ := json.Marshal(req)
	return b
}

func newTestServer(now time.Time) *Server {
	store := memory.New()
	registerSvc := service.NewRegisterService(store)
	registerSvc.SetNowFnForTest(func() time.Time { return now })
	messageSvc := service.NewMessageService(store)
	messageSvc.SetNowFnForTest(func() time.Time { return now })
	return NewServer(registerSvc, messageSvc)
}

func TestRegisterEndpointSuccess(t *testing.T) {
	now := time.Date(2026, 4, 22, 10, 30, 0, 0, time.UTC)
	srv := newTestServer(now)

	body := makeRegisterJSON(t, "44444444-4444-4444-4444-444444444444", now)
	r := httptest.NewRequest(http.MethodPost, "/users/register", bytes.NewReader(body))
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", w.Code, w.Body.String())
	}
}

func TestRegisterEndpointBadSignature(t *testing.T) {
	now := time.Date(2026, 4, 22, 10, 30, 0, 0, time.UTC)
	srv := newTestServer(now)

	payload := makeRegisterJSON(t, "55555555-5555-5555-5555-555555555555", now)
	var req map[string]any
	if err := json.Unmarshal(payload, &req); err != nil {
		t.Fatal(err)
	}
	req["nonce"] = base64.StdEncoding.EncodeToString([]byte("tamperednonce0001"))
	payload, _ = json.Marshal(req)

	r := httptest.NewRequest(http.MethodPost, "/users/register", bytes.NewReader(payload))
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, r)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d body=%s", w.Code, w.Body.String())
	}
}

func TestGetUserKeysEndpointSuccess(t *testing.T) {
	now := time.Date(2026, 4, 22, 10, 30, 0, 0, time.UTC)
	srv := newTestServer(now)

	userID := "66666666-6666-6666-6666-666666666666"
	regBody := makeRegisterJSON(t, userID, now)
	regReq := httptest.NewRequest(http.MethodPost, "/users/register", bytes.NewReader(regBody))
	regRes := httptest.NewRecorder()
	srv.Handler().ServeHTTP(regRes, regReq)
	if regRes.Code != http.StatusOK {
		t.Fatalf("register status=%d body=%s", regRes.Code, regRes.Body.String())
	}

	r := httptest.NewRequest(http.MethodGet, "/users/"+userID+"/keys", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", w.Code, w.Body.String())
	}
}

func TestGetUserKeysEndpointNotFound(t *testing.T) {
	now := time.Date(2026, 4, 22, 10, 30, 0, 0, time.UTC)
	srv := newTestServer(now)

	r := httptest.NewRequest(http.MethodGet, "/users/77777777-7777-7777-7777-777777777777/keys", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d body=%s", w.Code, w.Body.String())
	}
}

func TestPostMessageSuccess(t *testing.T) {
	now := time.Date(2026, 4, 22, 10, 30, 0, 0, time.UTC)
	srv := newTestServer(now)

	toUserID := "88888888-8888-8888-8888-888888888888"
	regBody := makeRegisterJSON(t, toUserID, now)
	srv.Handler().ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/users/register", bytes.NewReader(regBody)))

	r := httptest.NewRequest(http.MethodPost, "/messages", bytes.NewReader(makeMessageJSON(toUserID)))
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", w.Code, w.Body.String())
	}
}

func TestPostMessageRecipientNotFound(t *testing.T) {
	now := time.Date(2026, 4, 22, 10, 30, 0, 0, time.UTC)
	srv := newTestServer(now)

	r := httptest.NewRequest(http.MethodPost, "/messages", bytes.NewReader(makeMessageJSON("no-user")))
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d body=%s", w.Code, w.Body.String())
	}
}
