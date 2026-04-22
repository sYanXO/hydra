package service

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	"hydra/internal/protocol"
	storetypes "hydra/internal/store/types"
)

var ErrBadRequest = errors.New("bad_request")

type MessageStore interface {
	GetUser(userID string) (storetypes.User, bool, error)
	CreateMessage(m storetypes.Message) (bool, error)
	ListPendingMessages(toUserID string, limit int) ([]storetypes.Message, error)
	ListPendingMessagesByIDs(toUserID string, serverMessageIDs []string) ([]storetypes.Message, error)
	AckMessages(toUserID string, serverMessageIDs []string, ackedAt time.Time) (int, error)
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

type PollNotice struct {
	ServerMessageID string
	FromUserID      string
	ReceivedAt      time.Time
}

type AckedMessage struct {
	ServerMessageID string
	Envelope        protocol.MessageEnvelope
	ReceivedAt      time.Time
}

type AckResult struct {
	AckedCount int
	AckedAt    time.Time
	Messages   []AckedMessage
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

func (s *MessageService) PollMessages(userID string, limit int) ([]PollNotice, error) {
	if userID == "" {
		return nil, ErrBadRequest
	}
	if limit <= 0 {
		limit = 50
	}
	if limit > 100 {
		limit = 100
	}
	if _, ok, err := s.store.GetUser(userID); err != nil {
		return nil, ErrStoreFailure
	} else if !ok {
		return nil, ErrUserNotFound
	}

	rows, err := s.store.ListPendingMessages(userID, limit)
	if err != nil {
		return nil, ErrStoreFailure
	}
	out := make([]PollNotice, 0, len(rows))
	for _, m := range rows {
		out = append(out, PollNotice{
			ServerMessageID: m.ServerMessageID,
			FromUserID:      m.FromUserID,
			ReceivedAt:      m.ReceivedAt,
		})
	}
	return out, nil
}

func (s *MessageService) AckMessages(userID string, serverMessageIDs []string, ackedAt time.Time) (AckResult, error) {
	if userID == "" || len(serverMessageIDs) == 0 || ackedAt.IsZero() {
		return AckResult{}, ErrBadRequest
	}
	if _, ok, err := s.store.GetUser(userID); err != nil {
		return AckResult{}, ErrStoreFailure
	} else if !ok {
		return AckResult{}, ErrUserNotFound
	}

	pendingRows, err := s.store.ListPendingMessagesByIDs(userID, serverMessageIDs)
	if err != nil {
		return AckResult{}, ErrStoreFailure
	}

	count, err := s.store.AckMessages(userID, serverMessageIDs, ackedAt.UTC())
	if err != nil {
		return AckResult{}, ErrStoreFailure
	}

	acked := make([]AckedMessage, 0, len(pendingRows))
	for _, m := range pendingRows {
		var env protocol.MessageEnvelope
		if err := json.Unmarshal(m.EnvelopeJSON, &env); err != nil {
			continue
		}
		acked = append(acked, AckedMessage{
			ServerMessageID: m.ServerMessageID,
			Envelope:        env,
			ReceivedAt:      m.ReceivedAt,
		})
	}

	return AckResult{AckedCount: count, AckedAt: ackedAt.UTC(), Messages: acked}, nil
}

func newServerMessageID() string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "srv_unknown"
	}
	return "srv_" + hex.EncodeToString(b)
}
