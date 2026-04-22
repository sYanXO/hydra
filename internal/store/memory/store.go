package memory

import (
	"sort"
	"sync"
	"time"

	storetypes "hydra/internal/store/types"
)

type Store struct {
	mu       sync.RWMutex
	users    map[string]storetypes.User
	nonces   map[string]map[string]time.Time
	messages map[string]storetypes.Message
}

func New() *Store {
	return &Store{
		users:    make(map[string]storetypes.User),
		nonces:   make(map[string]map[string]time.Time),
		messages: make(map[string]storetypes.Message),
	}
}

func (s *Store) CreateUser(u storetypes.User) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.users[u.UserID]; ok {
		return false, nil
	}
	s.users[u.UserID] = u
	return true, nil
}

func (s *Store) GetUser(userID string) (storetypes.User, bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	u, ok := s.users[userID]
	return u, ok, nil
}

func (s *Store) CreateMessage(m storetypes.Message) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	k := m.FromUserID + "|" + m.ToUserID + "|" + m.MessageID
	if _, exists := s.messages[k]; exists {
		return false, nil
	}
	s.messages[k] = m
	return true, nil
}

func (s *Store) ListPendingMessages(toUserID string, limit int) ([]storetypes.Message, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]storetypes.Message, 0)
	for _, m := range s.messages {
		if m.ToUserID == toUserID && m.Status == "pending" {
			out = append(out, m)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].ReceivedAt.Before(out[j].ReceivedAt)
	})
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

func (s *Store) ListPendingMessagesByIDs(toUserID string, serverMessageIDs []string) ([]storetypes.Message, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	ids := make(map[string]struct{}, len(serverMessageIDs))
	for _, id := range serverMessageIDs {
		ids[id] = struct{}{}
	}
	out := make([]storetypes.Message, 0)
	for _, m := range s.messages {
		if m.ToUserID != toUserID || m.Status != "pending" {
			continue
		}
		if _, ok := ids[m.ServerMessageID]; !ok {
			continue
		}
		out = append(out, m)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].ReceivedAt.Before(out[j].ReceivedAt)
	})
	return out, nil
}

func (s *Store) AckMessages(toUserID string, serverMessageIDs []string, ackedAt time.Time) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ids := make(map[string]struct{}, len(serverMessageIDs))
	for _, id := range serverMessageIDs {
		ids[id] = struct{}{}
	}
	count := 0
	for k, m := range s.messages {
		if m.ToUserID != toUserID || m.Status != "pending" {
			continue
		}
		if _, ok := ids[m.ServerMessageID]; !ok {
			continue
		}
		m.Status = "delivered"
		t := ackedAt.UTC()
		m.DeliveredAt = &t
		m.ExpiresAt = t.Add(24 * time.Hour)
		s.messages[k] = m
		count++
	}
	return count, nil
}

func (s *Store) CheckAndStoreNonce(userID, nonce string, now time.Time, ttl time.Duration) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	userNonces, ok := s.nonces[userID]
	if !ok {
		userNonces = make(map[string]time.Time)
		s.nonces[userID] = userNonces
	}

	for n, created := range userNonces {
		if now.Sub(created) > ttl {
			delete(userNonces, n)
		}
	}

	if _, exists := userNonces[nonce]; exists {
		return false, nil
	}
	userNonces[nonce] = now
	return true, nil
}
