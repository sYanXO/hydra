package service

import (
	"errors"
	"time"

	"hydra/internal/protocol"
	storetypes "hydra/internal/store/types"
)

var (
	ErrUserNotFound = errors.New("user_not_found")
	ErrStoreFailure = errors.New("store_failure")
)

type RegisterStore interface {
	CreateUser(u storetypes.User) (bool, error)
	GetUser(userID string) (storetypes.User, bool, error)
	CheckAndStoreNonce(userID, nonce string, now time.Time, ttl time.Duration) (bool, error)
}

type RegisterService struct {
	store      RegisterStore
	skewWindow time.Duration
	nonceTTL   time.Duration
	nowFn      func() time.Time
}

func NewRegisterService(store RegisterStore) *RegisterService {
	return &RegisterService{
		store:      store,
		skewWindow: 5 * time.Minute,
		nonceTTL:   24 * time.Hour,
		nowFn:      time.Now,
	}
}

// SetNowFnForTest allows deterministic time-based tests.
func (s *RegisterService) SetNowFnForTest(fn func() time.Time) {
	s.nowFn = fn
}

type RegisterResult struct {
	UserID       string
	RegisteredAt time.Time
}

func (s *RegisterService) Register(req protocol.RegisterRequest) (RegisterResult, error) {
	if err := req.ValidateRequiredFields(); err != nil {
		return RegisterResult{}, errors.New("bad_request")
	}
	now := s.nowFn().UTC()
	if err := req.ValidateTimeWindow(now, s.skewWindow); err != nil {
		if errors.Is(err, protocol.ErrInvalidSignedAt) || errors.Is(err, protocol.ErrSignedAtSkew) {
			return RegisterResult{}, err
		}
		return RegisterResult{}, errors.New("bad_request")
	}
	if err := req.VerifySignature(); err != nil {
		return RegisterResult{}, err
	}
	ok, err := s.store.CheckAndStoreNonce(req.UserID, req.Nonce, now, s.nonceTTL)
	if err != nil {
		return RegisterResult{}, ErrStoreFailure
	}
	if !ok {
		return RegisterResult{}, protocol.ErrNonceReuse
	}
	ok, err = s.store.CreateUser(storetypes.User{
		UserID:             req.UserID,
		IdentityKeyEd25519: req.IdentityKeyEd25519,
		DHKeyX25519:        req.DHKeyX25519,
		CreatedAt:          now,
		UpdatedAt:          now,
	})
	if err != nil {
		return RegisterResult{}, ErrStoreFailure
	}
	if !ok {
		return RegisterResult{}, protocol.ErrUserAlreadyExists
	}
	return RegisterResult{UserID: req.UserID, RegisteredAt: now}, nil
}

type UserKeysResult struct {
	UserID             string
	IdentityKeyEd25519 string
	DHKeyX25519        string
	KeysetVersion      int
	UpdatedAt          time.Time
}

func (s *RegisterService) GetUserKeys(userID string) (UserKeysResult, error) {
	u, ok, err := s.store.GetUser(userID)
	if err != nil {
		return UserKeysResult{}, ErrStoreFailure
	}
	if !ok {
		return UserKeysResult{}, ErrUserNotFound
	}
	return UserKeysResult{
		UserID:             u.UserID,
		IdentityKeyEd25519: u.IdentityKeyEd25519,
		DHKeyX25519:        u.DHKeyX25519,
		KeysetVersion:      1,
		UpdatedAt:          u.UpdatedAt,
	}, nil
}
