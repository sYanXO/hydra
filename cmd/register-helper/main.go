package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"hydra/internal/protocol"
)

func main() {
	server := flag.String("server", "http://localhost:8080", "Hydra server base URL")
	userID := flag.String("user-id", randomUserID(), "User ID")
	send := flag.Bool("send", false, "Send payload to /users/register")
	flag.Parse()

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		die("generate ed25519 key: %v", err)
	}

	dhPub := make([]byte, 32)
	if _, err := rand.Read(dhPub); err != nil {
		die("generate dh key bytes: %v", err)
	}
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		die("generate nonce: %v", err)
	}

	req := protocol.RegisterRequest{
		UserID:             *userID,
		IdentityKeyEd25519: base64.StdEncoding.EncodeToString(pub),
		DHKeyX25519:        base64.StdEncoding.EncodeToString(dhPub),
		Nonce:              base64.StdEncoding.EncodeToString(nonce),
		SignedAt:           time.Now().UTC().Format(time.RFC3339),
	}
	req.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(priv, []byte(req.CanonicalString())))

	payload, err := json.MarshalIndent(req, "", "  ")
	if err != nil {
		die("marshal payload: %v", err)
	}

	fmt.Println(string(payload))
	fmt.Printf("\nuser_id=%s\n", req.UserID)

	if !*send {
		return
	}

	endpoint := *server + "/users/register"
	httpReq, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(payload))
	if err != nil {
		die("build request: %v", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(httpReq)
	if err != nil {
		die("send request: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	fmt.Printf("status=%d\n%s\n", resp.StatusCode, string(body))
}

func randomUserID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	hexStr := hex.EncodeToString(b)
	return fmt.Sprintf("%s-%s-%s-%s-%s", hexStr[0:8], hexStr[8:12], hexStr[12:16], hexStr[16:20], hexStr[20:32])
}

func die(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}
