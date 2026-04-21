.PHONY: help up-db down-db logs-db migrate test run run-memory run-postgres fmt fmt-check tidy deps-check

DB_URL ?= postgres://hydra:hydra@localhost:5432/hydra?sslmode=disable

help:
	@echo "Available targets:"
	@echo "  up-db         Start local Postgres via docker compose"
	@echo "  down-db       Stop local Postgres"
	@echo "  logs-db       Tail Postgres logs"
	@echo "  migrate       Apply SQL migrations (docker if available, else host psql)"
	@echo "  test          Run Go tests"
	@echo "  fmt           Run gofmt (writes changes)"
	@echo "  fmt-check     Verify gofmt is clean (no writes)"
	@echo "  tidy          Run go mod tidy"
	@echo "  deps-check    Verify module integrity and no tidy drift"
	@echo "  run-memory    Run server with in-memory store"
	@echo "  run-postgres  Run server with Postgres store"
	@echo "  run           Alias of run-memory"

up-db:
	docker compose up -d postgres

down-db:
	docker compose down

logs-db:
	docker compose logs -f postgres

migrate:
	@if command -v docker >/dev/null 2>&1; then \
		set -e; \
		docker compose up -d postgres; \
		echo "waiting for postgres to be ready..."; \
		for i in $$(seq 1 30); do \
			if docker compose exec -T postgres pg_isready -U hydra -d hydra >/dev/null 2>&1; then \
				break; \
			fi; \
			sleep 1; \
		done; \
		docker compose exec -T postgres pg_isready -U hydra -d hydra >/dev/null; \
		for f in $$(ls migrations/*.sql | sort); do \
			echo "applying $$f via docker"; \
			docker compose exec -T postgres psql -h localhost -U hydra -d hydra -v ON_ERROR_STOP=1 -f /dev/stdin < $$f; \
		done; \
	elif command -v psql >/dev/null 2>&1; then \
		set -e; \
		for f in $$(ls migrations/*.sql | sort); do \
			echo "applying $$f via host psql"; \
			psql "$(DB_URL)" -v ON_ERROR_STOP=1 -f $$f; \
		done; \
	else \
		echo "error: neither docker nor psql is available in PATH"; \
		echo "install Docker Desktop/Engine OR install postgresql-client (psql)"; \
		exit 127; \
	fi

test:
	go test ./...

fmt:
	gofmt -w $$(find . -name '*.go')

fmt-check:
	@unformatted=$$(gofmt -l $$(find . -name '*.go')); \
	if [ -n "$$unformatted" ]; then \
		echo "Files not formatted:"; \
		echo "$$unformatted"; \
		exit 1; \
	fi

tidy:
	go mod tidy

deps-check:
	go mod verify
	@cp go.mod /tmp/hydra.go.mod.tmp && cp go.sum /tmp/hydra.go.sum.tmp
	@go mod tidy
	@diff -u /tmp/hydra.go.mod.tmp go.mod
	@diff -u /tmp/hydra.go.sum.tmp go.sum

run-memory:
	HYDRA_STORE=memory HYDRA_ADDR=:8080 go run ./cmd/server

run-postgres:
	HYDRA_STORE=postgres HYDRA_DATABASE_URL="$(DB_URL)" HYDRA_ADDR=:8080 go run ./cmd/server

run: run-memory
