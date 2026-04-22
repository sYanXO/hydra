package postgres

import (
	"database/sql"
	"fmt"
	"os"
	"testing"
	"time"

	storetypes "hydra/internal/store/types"

	_ "github.com/jackc/pgx/v5/stdlib"
)

func TestAckMessagesPostgresRegression(t *testing.T) {
	dsn := os.Getenv("HYDRA_TEST_DATABASE_URL")
	if dsn == "" {
		dsn = "postgres://hydra:hydra@localhost:5432/hydra?sslmode=disable"
	}

	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer db.Close()

	if err := db.Ping(); err != nil {
		t.Skipf("postgres not available: %v", err)
	}

	var hasMessagesTable bool
	err = db.QueryRow(`SELECT to_regclass('public.messages') IS NOT NULL`).Scan(&hasMessagesTable)
	if err != nil {
		t.Fatalf("check messages table: %v", err)
	}
	if !hasMessagesTable {
		t.Skip("messages table not found; run migrations first")
	}

	s := New(db)
	now := time.Now().UTC().Truncate(time.Second)
	suffix := fmt.Sprintf("%d", time.Now().UTC().UnixNano())
	toUserID := "test_to_" + suffix
	fromUserID := "test_from_" + suffix

	_, err = s.CreateUser(storetypes.User{
		UserID:             toUserID,
		IdentityKeyEd25519: "AQ==",
		DHKeyX25519:        "AQ==",
		CreatedAt:          now,
		UpdatedAt:          now,
	})
	if err != nil {
		t.Fatalf("create to user: %v", err)
	}
	_, err = s.CreateUser(storetypes.User{
		UserID:             fromUserID,
		IdentityKeyEd25519: "AQ==",
		DHKeyX25519:        "AQ==",
		CreatedAt:          now,
		UpdatedAt:          now,
	})
	if err != nil {
		t.Fatalf("create from user: %v", err)
	}

	serverMessageID := "srv_test_" + suffix
	_, err = s.CreateMessage(storetypes.Message{
		ServerMessageID: serverMessageID,
		ToUserID:        toUserID,
		FromUserID:      fromUserID,
		MessageID:       "11111111-1111-4111-8111-111111111111",
		EnvelopeJSON:    []byte(`{"message":"hello"}`),
		Status:          "pending",
		ReceivedAt:      now,
		ExpiresAt:       now.Add(14 * 24 * time.Hour),
	})
	if err != nil {
		t.Fatalf("create message: %v", err)
	}

	ackedAt := now.Add(10 * time.Second)
	count, err := s.AckMessages(toUserID, []string{serverMessageID}, ackedAt)
	if err != nil {
		t.Fatalf("ack messages: %v", err)
	}
	if count != 1 {
		t.Fatalf("expected ack count 1, got %d", count)
	}
}
