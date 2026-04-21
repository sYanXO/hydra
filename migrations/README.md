# Migrations (v0)

Apply SQL files in lexical order.

Example (local):

```bash
psql "postgres://hydra:hydra@localhost:5432/hydra?sslmode=disable" -f migrations/0001_init.sql
```

Current scope:
- users
- registration_nonces

Messages and auth tables will be added in later sprints per plan.
