package service

import (
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"regexp"
	"strings"
	"time"

	"hydra/internal/protocol"
	storetypes "hydra/internal/store/types"
)

var (
	ErrUserNotFound    = errors.New("user_not_found")
	ErrStoreFailure    = errors.New("store_failure")
	ErrInvalidUsername = errors.New("invalid_username")
)

var (
	usernameNormPattern  = regexp.MustCompile(`^[a-z0-9_]{3,20}$`)
	discriminatorPattern = regexp.MustCompile(`^[0-9]{4}$`)
)

type RegisterStore interface {
	CreateUser(u storetypes.User) (bool, error)
	GetUser(userID string) (storetypes.User, bool, error)
	GetUserByHandle(usernameNorm, discriminator string) (storetypes.User, bool, error)
	CreateHandle(h storetypes.UserHandle) (bool, error)
	GetActiveHandle(userID string) (storetypes.UserHandle, bool, error)
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

type UserHandle struct {
	UsernameNorm  string
	Discriminator string
}

func (h UserHandle) Full() string {
	if h.UsernameNorm == "" || h.Discriminator == "" {
		return ""
	}
	return h.UsernameNorm + "#" + h.Discriminator
}

type RegisterResult struct {
	UserID       string
	RegisteredAt time.Time
	Handle       UserHandle
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

	handle, err := s.allocateHandle(req.UserID, req.RequestedUsername, now)
	if err != nil {
		return RegisterResult{}, err
	}
	return RegisterResult{UserID: req.UserID, RegisteredAt: now, Handle: handle}, nil
}

type UserKeysResult struct {
	UserID             string
	IdentityKeyEd25519 string
	DHKeyX25519        string
	KeysetVersion      int
	UpdatedAt          time.Time
	Handle             UserHandle
}

func (s *RegisterService) GetUserKeys(userID string) (UserKeysResult, error) {
	u, ok, err := s.store.GetUser(userID)
	if err != nil {
		return UserKeysResult{}, ErrStoreFailure
	}
	if !ok {
		return UserKeysResult{}, ErrUserNotFound
	}
	h, ok, err := s.store.GetActiveHandle(userID)
	if err != nil {
		return UserKeysResult{}, ErrStoreFailure
	}
	if !ok {
		return UserKeysResult{}, ErrStoreFailure
	}
	return UserKeysResult{
		UserID:             u.UserID,
		IdentityKeyEd25519: u.IdentityKeyEd25519,
		DHKeyX25519:        u.DHKeyX25519,
		KeysetVersion:      1,
		UpdatedAt:          u.UpdatedAt,
		Handle: UserHandle{
			UsernameNorm:  h.UsernameNorm,
			Discriminator: h.Discriminator,
		},
	}, nil
}

func (s *RegisterService) GetUserKeysByHandle(username, discriminator string) (UserKeysResult, error) {
	norm, err := normalizeRequestedUsername(username)
	if err != nil {
		return UserKeysResult{}, ErrInvalidUsername
	}
	if !discriminatorPattern.MatchString(discriminator) {
		return UserKeysResult{}, ErrInvalidUsername
	}
	u, ok, err := s.store.GetUserByHandle(norm, discriminator)
	if err != nil {
		return UserKeysResult{}, ErrStoreFailure
	}
	if !ok {
		return UserKeysResult{}, ErrUserNotFound
	}
	return s.GetUserKeys(u.UserID)
}

func (s *RegisterService) allocateHandle(userID, requestedUsername string, now time.Time) (UserHandle, error) {
	base := fallbackUsername(userID)
	if strings.TrimSpace(requestedUsername) != "" {
		norm, err := normalizeRequestedUsername(requestedUsername)
		if err != nil {
			return UserHandle{}, ErrInvalidUsername
		}
		base = norm
	}

	for i := 0; i < 50; i++ {
		disc := randomDiscriminator()
		ok, err := s.store.CreateHandle(storetypes.UserHandle{
			UserID:        userID,
			UsernameNorm:  base,
			Discriminator: disc,
			Active:        true,
			CreatedAt:     now,
		})
		if err != nil {
			return UserHandle{}, ErrStoreFailure
		}
		if ok {
			return UserHandle{UsernameNorm: base, Discriminator: disc}, nil
		}
	}
	return UserHandle{}, ErrStoreFailure
}

func normalizeRequestedUsername(in string) (string, error) {
	norm := strings.ToLower(strings.TrimSpace(in))
	norm = strings.ReplaceAll(norm, " ", "_")
	if !usernameNormPattern.MatchString(norm) {
		return "", ErrInvalidUsername
	}
	switch norm {
	case "admin", "support", "system":
		return "", ErrInvalidUsername
	}
	return norm, nil
}

func fallbackUsername(userID string) string {
	r := strings.NewReplacer("-", "", ".", "", " ", "")
	compact := r.Replace(strings.ToLower(userID))
	if len(compact) < 8 {
		compact = compact + "user0000"
	}
	return "u_" + compact[:8]
}

func randomDiscriminator() string {
	n, err := rand.Int(rand.Reader, big.NewInt(10000))
	if err != nil {
		return "0001"
	}
	return fmt.Sprintf("%04d", n.Int64())
}
