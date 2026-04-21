# Hydra Backend Dependency Allowlist (v1)

> Principle: stdlib-first, minimal external surface. Build protocol and business logic in-house.

This file defines the approved dependency baseline for the Go backend.
Any dependency outside this list requires explicit approval.

---

## 1) Allowed by default

## Go standard library (preferred)
Use stdlib whenever possible:
- `net/http` (HTTP server)
- `database/sql` (DB abstraction)
- `context`, `time`, `errors`, `encoding/json`
- `crypto/ed25519`, `crypto/rand`, `crypto/sha256`, `crypto/hmac`
- `log/slog` (with redaction discipline)

Rationale:
- Lower supply-chain risk
- Long-term maintenance stability
- Minimal transitive dependencies

---

## 2) External dependencies allowlist (initial)

1. PostgreSQL driver
   - Preferred: `github.com/jackc/pgx/v5` (via stdlib compatibility where useful)
   - Purpose: PostgreSQL connectivity only
   - Notes: avoid ORM layers

2. WebSocket transport
   - Preferred: `github.com/gorilla/websocket` (or another actively maintained minimal WS library if policy changes)
   - Purpose: realtime message push
   - Notes: keep usage thin behind internal interface

3. Crypto implementation or binding
   - Preferred path A: use Go stdlib primitives where they match locked protocol requirements
   - Preferred path B: vetted NaCl or libsodium-compatible package only if required for exact primitive parity
   - Purpose: X25519 and Ed25519, AEAD-compatible construction, constant-time safe operations
   - Notes: never implement primitives from scratch

4. UUID generation
   - Preferred: `github.com/google/uuid`
   - Purpose: user and message IDs
   - Notes: can be replaced with internal generator if needed

---

## 3) Explicitly disallowed by default

- Heavy web frameworks (unless approved)
- ORMs and query layers that hide SQL behavior
- Generic utility mega libraries
- Telemetry SDKs that capture request bodies by default
- Any dependency that increases metadata exposure risk

---

## 4) Dependency approval checklist (required for new additions)

Every new dependency PR must include:
1. Why stdlib or in-house is insufficient
2. Security posture
   - maintenance status
   - known CVEs or advisories
   - release cadence
3. Transitive dependency impact
4. Data handling review
   - does it log request bodies, IPs, or headers by default?
5. Exit strategy
   - how to replace or remove if needed

Approval requires sign-off from:
- backend owner
- security reviewer

---

## 5) CI enforcement

- Pin exact versions in `go.mod` and `go.sum`
- Add dependency diff check in CI for PRs
- Run `govulncheck` in CI
- Fail build if unapproved dependency appears

---

## 6) Internal package boundaries (to keep deps contained)

Recommended backend package layout:
- `internal/transport/http` (handlers, auth middleware)
- `internal/transport/ws` (websocket event delivery)
- `internal/store/postgres` (all SQL and migrations)
- `internal/crypto` (signing, key agreement, encryption wrappers)
- `internal/protocol` (canonical string building, schema validation)
- `internal/service` (business logic)

Rule:
- external dependencies should be imported only at boundary packages where possible.

---

## 7) Review cadence

- Re-review allowlist once per sprint (v0 to v4)
- Remove unused dependencies aggressively
- Track dependency count trend as a quality metric
