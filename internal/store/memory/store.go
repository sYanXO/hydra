package memory

import (
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
