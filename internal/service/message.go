package service

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"time"

	"hydra/internal/protocol"
	storetypes "hydra/internal/store/types"
)

type MessageStore interface {
	GetUser(userID string) (storetypes.User, bool, error)
	CreateMessage(m storetypes.Message) (bool, error)
}

type MessageService struct {
	store MessageStore
	nowFn func() time.Time
}

func NewMessageService(store MessageStore) *MessageService {
	return &MessageService{store: store, nowFn: time.Now}
}

func (s *MessageService) SetNowFnForTest(fn func() time.Time) {
	s.nowFn = fn
}

type MessageResult struct {
	ServerMessageID string
	ReceivedAt      time.Time
}

func (s *MessageService) SendMessage(env protocol.MessageEnvelope) (MessageResult, error) {
	if err := env.ValidateBasic(); err != nil {
		return MessageResult{}, protocol.ErrInvalidEnvelope
	}
	if _, ok, err := s.store.GetUser(env.ToUserID); err != nil {
		return MessageResult{}, ErrStoreFailure
	} else if !ok {
		return MessageResult{}, protocol.ErrRecipientNotFound
	}

	now := s.nowFn().UTC()
	envBytes, err := json.Marshal(env)
	if err != nil {
		return MessageResult{}, protocol.ErrInvalidEnvelope
	}
	serverMessageID := newServerMessageID()
	created, err := s.store.CreateMessage(storetypes.Message{
		ServerMessageID: serverMessageID,
		ToUserID:        env.ToUserID,
		FromUserID:      env.FromUserID,
		MessageID:       env.MessageID,
		EnvelopeJSON:    envBytes,
		Status:          "pending",
		ReceivedAt:      now,
		ExpiresAt:       now.Add(14 * 24 * time.Hour),
	})
	if err != nil {
		return MessageResult{}, ErrStoreFailure
	}
	if !created {
		return MessageResult{}, protocol.ErrDuplicateMessage
	}
	return MessageResult{ServerMessageID: serverMessageID, ReceivedAt: now}, nil
}

func newServerMessageID() string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "srv_unknown"
	}
	return "srv_" + hex.EncodeToString(b)
}
