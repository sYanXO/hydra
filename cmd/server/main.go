package main

import (
	"database/sql"
	"log"
	"net/http"
	"os"
	"time"

	"hydra/internal/service"
	"hydra/internal/store/memory"
	"hydra/internal/store/postgres"
	httptransport "hydra/internal/transport/http"

	_ "github.com/jackc/pgx/v5/stdlib"
)

func main() {
	addr := getenv("HYDRA_ADDR", ":8080")
	storeMode := getenv("HYDRA_STORE", "memory")

	registerStore, cleanup := buildRegisterStore(storeMode)
	defer cleanup()

	registerService := service.NewRegisterService(registerStore)
	messageService := service.NewMessageService(registerStore)
	server := httptransport.NewServer(registerService, messageService)

	log.Printf("hydra backend listening on %s (store=%s)", addr, storeMode)
	if err := http.ListenAndServe(addr, server.Handler()); err != nil {
		log.Fatal(err)
	}
}

type backendStore interface {
	service.RegisterStore
	service.MessageStore
}

func buildRegisterStore(mode string) (backendStore, func()) {
	if mode != "postgres" {
		return memory.New(), func() {}
	}

	dsn := os.Getenv("HYDRA_DATABASE_URL")
	if dsn == "" {
		log.Fatal("HYDRA_DATABASE_URL is required when HYDRA_STORE=postgres")
	}

	db, err := sql.Open("pgx", dsn)
	if err != nil {
		log.Fatalf("open database: %v", err)
	}
	db.SetMaxOpenConns(10)
	db.SetMaxIdleConns(5)
	db.SetConnMaxLifetime(30 * time.Minute)

	if err := db.Ping(); err != nil {
		log.Fatalf("ping database: %v", err)
	}

	return postgres.New(db), func() { _ = db.Close() }
}

func getenv(key, fallback string) string {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	return v
}
