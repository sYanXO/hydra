package postgres

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"
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

func (s *Store) CreateMessage(m storetypes.Message) (bool, error) {
	res, err := s.db.Exec(`
		INSERT INTO messages (server_message_id, to_user_id, from_user_id, message_id, envelope_json, status, received_at, expires_at)
		VALUES ($1, $2, $3, $4, $5::jsonb, $6, $7, $8)
		ON CONFLICT (from_user_id, to_user_id, message_id) DO NOTHING
	`, m.ServerMessageID, m.ToUserID, m.FromUserID, m.MessageID, string(m.EnvelopeJSON), m.Status, m.ReceivedAt, m.ExpiresAt)
	if err != nil {
		return false, err
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return false, err
	}
	return affected == 1, nil
}

func (s *Store) ListPendingMessages(toUserID string, limit int) ([]storetypes.Message, error) {
	rows, err := s.db.Query(`
		SELECT server_message_id, to_user_id, from_user_id, message_id, envelope_json, status, received_at, delivered_at, expires_at
		FROM messages
		WHERE to_user_id = $1 AND status = 'pending'
		ORDER BY received_at ASC
		LIMIT $2
	`, toUserID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]storetypes.Message, 0)
	for rows.Next() {
		var m storetypes.Message
		var deliveredAt sql.NullTime
		if err := rows.Scan(&m.ServerMessageID, &m.ToUserID, &m.FromUserID, &m.MessageID, &m.EnvelopeJSON, &m.Status, &m.ReceivedAt, &deliveredAt, &m.ExpiresAt); err != nil {
			return nil, err
		}
		if deliveredAt.Valid {
			t := deliveredAt.Time.UTC()
			m.DeliveredAt = &t
		}
		out = append(out, m)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func (s *Store) ListPendingMessagesByIDs(toUserID string, serverMessageIDs []string) ([]storetypes.Message, error) {
	if len(serverMessageIDs) == 0 {
		return []storetypes.Message{}, nil
	}
	placeholders := make([]string, len(serverMessageIDs))
	args := make([]any, 0, len(serverMessageIDs)+1)
	args = append(args, toUserID)
	for i, id := range serverMessageIDs {
		placeholders[i] = fmt.Sprintf("$%d", i+2)
		args = append(args, id)
	}
	query := fmt.Sprintf(`
		SELECT server_message_id, to_user_id, from_user_id, message_id, envelope_json, status, received_at, delivered_at, expires_at
		FROM messages
		WHERE to_user_id = $1 AND status = 'pending' AND server_message_id IN (%s)
		ORDER BY received_at ASC
	`, strings.Join(placeholders, ","))
	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]storetypes.Message, 0)
	for rows.Next() {
		var m storetypes.Message
		var deliveredAt sql.NullTime
		if err := rows.Scan(&m.ServerMessageID, &m.ToUserID, &m.FromUserID, &m.MessageID, &m.EnvelopeJSON, &m.Status, &m.ReceivedAt, &deliveredAt, &m.ExpiresAt); err != nil {
			return nil, err
		}
		if deliveredAt.Valid {
			t := deliveredAt.Time.UTC()
			m.DeliveredAt = &t
		}
		out = append(out, m)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func (s *Store) AckMessages(toUserID string, serverMessageIDs []string, ackedAt time.Time) (int, error) {
	if len(serverMessageIDs) == 0 {
		return 0, nil
	}
	placeholders := make([]string, len(serverMessageIDs))
	args := make([]any, 0, len(serverMessageIDs)+2)
	args = append(args, ackedAt.UTC(), toUserID)
	for i, id := range serverMessageIDs {
		placeholders[i] = fmt.Sprintf("$%d", i+3)
		args = append(args, id)
	}

	query := fmt.Sprintf(`
		UPDATE messages
		SET status = 'delivered', delivered_at = $1::timestamptz, expires_at = ($1::timestamptz + interval '24 hours')
		WHERE to_user_id = $2 AND status = 'pending' AND server_message_id IN (%s)
	`, strings.Join(placeholders, ","))
	res, err := s.db.Exec(query, args...)
	if err != nil {
		return 0, err
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return 0, err
	}
	return int(affected), nil
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
