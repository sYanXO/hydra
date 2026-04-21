# Hydra

Hydra is an early stage private 1 on 1 chat backend.

The immediate goal is to prove end to end key registration and key lookup with a server that only stores public keys and encrypted payloads.

## Local setup

Requirements:
- Go (version from `go.mod`)
- Docker and Docker Compose
- `psql`

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

## Quality checks

```bash
make fmt-check
make test
```
