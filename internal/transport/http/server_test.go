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
	var resp map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	h, _ := resp["handle"].(map[string]any)
	if h == nil || h["full"] == "" {
		t.Fatalf("expected handle in register response: %s", w.Body.String())
	}
}

func TestGetUserKeysEndpointSuccess(t *testing.T) {
	now := time.Date(2026, 4, 22, 10, 30, 0, 0, time.UTC)
	srv := newTestServer(now)

	userID := "66666666-6666-6666-6666-666666666666"
	regBody := makeRegisterJSON(t, userID, now)
	srv.Handler().ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/users/register", bytes.NewReader(regBody)))

	r := httptest.NewRequest(http.MethodGet, "/users/"+userID+"/keys", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", w.Code, w.Body.String())
	}
	var keysResp map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &keysResp)
	handle, _ := keysResp["handle"].(map[string]any)
	if handle == nil {
		t.Fatalf("expected handle in keys response: %s", w.Body.String())
	}
	username, _ := handle["username"].(string)
	discriminator, _ := handle["discriminator"].(string)
	if username == "" || discriminator == "" {
		t.Fatalf("invalid handle in keys response: %s", w.Body.String())
	}

	byHandleReq := httptest.NewRequest(http.MethodGet, "/users/by-handle/"+username+"/"+discriminator+"/keys", nil)
	byHandleW := httptest.NewRecorder()
	srv.Handler().ServeHTTP(byHandleW, byHandleReq)
	if byHandleW.Code != http.StatusOK {
		t.Fatalf("by-handle status = %d body=%s", byHandleW.Code, byHandleW.Body.String())
	}
}

func TestPostPollAckFlow(t *testing.T) {
	now := time.Date(2026, 4, 22, 10, 30, 0, 0, time.UTC)
	srv := newTestServer(now)

	toUserID := "88888888-8888-8888-8888-888888888888"
	regBody := makeRegisterJSON(t, toUserID, now)
	srv.Handler().ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/users/register", bytes.NewReader(regBody)))

	postW := httptest.NewRecorder()
	srv.Handler().ServeHTTP(postW, httptest.NewRequest(http.MethodPost, "/messages", bytes.NewReader(makeMessageJSON(toUserID))))
	if postW.Code != http.StatusOK {
		t.Fatalf("post status = %d body=%s", postW.Code, postW.Body.String())
	}

	var postResp map[string]any
	_ = json.Unmarshal(postW.Body.Bytes(), &postResp)
	serverMsgID, _ := postResp["server_message_id"].(string)
	if serverMsgID == "" {
		t.Fatalf("expected server_message_id")
	}

	pollReq := httptest.NewRequest(http.MethodGet, "/messages/poll?user_id="+toUserID+"&limit=50", nil)
	pollW := httptest.NewRecorder()
	srv.Handler().ServeHTTP(pollW, pollReq)
	if pollW.Code != http.StatusOK {
		t.Fatalf("poll status = %d body=%s", pollW.Code, pollW.Body.String())
	}
	var pollResp1 map[string]any
	_ = json.Unmarshal(pollW.Body.Bytes(), &pollResp1)
	m1, _ := pollResp1["messages"].([]any)
	if len(m1) != 1 {
		t.Fatalf("expected 1 poll notice, got %d", len(m1))
	}

	ackBody := map[string]any{
		"user_id":            toUserID,
		"server_message_ids": []string{serverMsgID},
		"acked_at":           now.Format(time.RFC3339),
	}
	ackJSON, _ := json.Marshal(ackBody)
	ackReq := httptest.NewRequest(http.MethodPost, "/messages/ack", bytes.NewReader(ackJSON))
	ackW := httptest.NewRecorder()
	srv.Handler().ServeHTTP(ackW, ackReq)
	if ackW.Code != http.StatusOK {
		t.Fatalf("ack status = %d body=%s", ackW.Code, ackW.Body.String())
	}
	var ackResp map[string]any
	_ = json.Unmarshal(ackW.Body.Bytes(), &ackResp)
	ackedMsgs, _ := ackResp["messages"].([]any)
	if len(ackedMsgs) != 1 {
		t.Fatalf("expected 1 acked message payload, got %d", len(ackedMsgs))
	}

	pollW2 := httptest.NewRecorder()
	srv.Handler().ServeHTTP(pollW2, pollReq)
	var pollResp map[string]any
	_ = json.Unmarshal(pollW2.Body.Bytes(), &pollResp)
	msgs, _ := pollResp["messages"].([]any)
	if len(msgs) != 0 {
		t.Fatalf("expected 0 pending messages after ack, got %d", len(msgs))
	}
}
