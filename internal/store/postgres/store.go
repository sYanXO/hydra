package postgres

import (
	"database/sql"
	"errors"
	"time"

	storetypes "hydra/internal/store/types"
)

type Store struct {
	db *sql.DB
}

func New(db *sql.DB) *Store {
	return &Store{db: db}
}

func (s *Store) CreateUser(u storetypes.User) (bool, error) {
	res, err := s.db.Exec(`
		INSERT INTO users (user_id, identity_key_ed25519, dh_key_x25519, keyset_version, created_at, updated_at)
		VALUES ($1, $2, $3, 1, $4, $5)
		ON CONFLICT (user_id) DO NOTHING
	`, u.UserID, u.IdentityKeyEd25519, u.DHKeyX25519, u.CreatedAt, u.UpdatedAt)
	if err != nil {
		return false, err
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return false, err
	}
	return affected == 1, nil
}

func (s *Store) GetUser(userID string) (storetypes.User, bool, error) {
	var u storetypes.User
	var keysetVersion int
	err := s.db.QueryRow(`
		SELECT user_id, identity_key_ed25519, dh_key_x25519, keyset_version, created_at, updated_at
		FROM users
		WHERE user_id = $1
	`, userID).Scan(&u.UserID, &u.IdentityKeyEd25519, &u.DHKeyX25519, &keysetVersion, &u.CreatedAt, &u.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return storetypes.User{}, false, nil
	}
	if err != nil {
		return storetypes.User{}, false, err
	}
	return u, true, nil
}

func (s *Store) CheckAndStoreNonce(userID, nonce string, now time.Time, ttl time.Duration) (bool, error) {
	_, err := s.db.Exec(`
		DELETE FROM registration_nonces
		WHERE user_id = $1 AND created_at < $2
	`, userID, now.Add(-ttl))
	if err != nil {
		return false, err
	}

	res, err := s.db.Exec(`
		INSERT INTO registration_nonces (user_id, nonce, signed_at, created_at)
		VALUES ($1, $2, $3, $4)
		ON CONFLICT (user_id, nonce) DO NOTHING
	`, userID, nonce, now, now)
	if err != nil {
		return false, err
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return false, err
	}
	return affected == 1, nil
}
