# Hydra

Hydra is an early stage private 1 on 1 chat backend.

The immediate goal is to prove end to end key registration and key lookup with a server that only stores public keys and encrypted payloads.

## Local setup

Requirements:
- Go (version from `go.mod`)
- Docker and Docker Compose

Start database:

```bash
make up-db
```

Apply migration:

```bash
make migrate
```

Run server with Postgres:

```bash
make run-postgres
```

Run web client (Vite + React + Tailwind):

```bash
cd web
npm install
npm run dev
```

Open web app:
- http://localhost:5173/

Health check:

```bash
curl -s http://localhost:8080/health
```

## Manual registration test

Generate a signed payload and send it:

```bash
go run ./cmd/register-helper --send
```

Generate payload only:

```bash
go run ./cmd/register-helper
```

Lookup keys after registration:

```bash
curl -s http://localhost:8080/users/<user_id>/keys
```

## Web flow

1. Open http://localhost:8080/
2. Generate local identity
3. Register on server
4. On another browser profile, repeat and copy user id
5. Send message to the other user id
6. Poll inbox and ack messages

## Quality checks

```bash
make fmt-check
make test
```
