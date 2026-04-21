package httptransport

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"hydra/internal/protocol"
	"hydra/internal/service"
)

type Server struct {
	registerService *service.RegisterService
	mux             *http.ServeMux
}

func NewServer(registerService *service.RegisterService) *Server {
	s := &Server{registerService: registerService, mux: http.NewServeMux()}
	s.routes()
	return s
}

func (s *Server) Handler() http.Handler {
	return s.mux
}

func (s *Server) routes() {
	s.mux.HandleFunc("GET /health", s.handleHealth)
	s.mux.HandleFunc("POST /users/register", s.handleRegister)
	s.mux.HandleFunc("GET /users/{id}/keys", s.handleGetUserKeys)
}

func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "time": time.Now().UTC().Format(time.RFC3339)})
}

func (s *Server) handleRegister(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	var req protocol.RegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", "Malformed JSON.", false)
		return
	}

	result, err := s.registerService.Register(req)
	if err != nil {
		switch {
		case errors.Is(err, protocol.ErrInvalidSignedAt):
			writeError(w, http.StatusBadRequest, "invalid_signed_at", "signed_at must be RFC3339 UTC.", false)
		case errors.Is(err, protocol.ErrSignedAtSkew):
			writeError(w, http.StatusBadRequest, "signed_at_out_of_window", "signed_at is outside allowed window.", false)
		case errors.Is(err, protocol.ErrInvalidBase64):
			writeError(w, http.StatusBadRequest, "invalid_base64", "One or more base64 fields are invalid.", false)
		case errors.Is(err, protocol.ErrInvalidPublicKey):
			writeError(w, http.StatusBadRequest, "invalid_public_key", "Identity public key is invalid.", false)
		case errors.Is(err, protocol.ErrInvalidSignature):
			writeError(w, http.StatusUnauthorized, "invalid_signature", "Signature verification failed.", false)
		case errors.Is(err, protocol.ErrNonceReuse):
			writeError(w, http.StatusConflict, "nonce_reused", "Nonce has already been used for this user.", false)
		case errors.Is(err, protocol.ErrUserAlreadyExists):
			writeError(w, http.StatusConflict, "user_already_registered", "User already exists.", false)
		default:
			if err.Error() == "bad_request" {
				writeError(w, http.StatusBadRequest, "bad_request", "Missing required fields.", false)
				return
			}
			writeError(w, http.StatusInternalServerError, "internal_error", "Internal server error.", true)
		}
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"ok":            true,
		"user_id":       result.UserID,
		"registered_at": result.RegisteredAt.Format(time.RFC3339),
	})
}

func (s *Server) handleGetUserKeys(w http.ResponseWriter, r *http.Request) {
	userID := r.PathValue("id")
	if userID == "" {
		writeError(w, http.StatusBadRequest, "bad_request", "Missing user id.", false)
		return
	}
	result, err := s.registerService.GetUserKeys(userID)
	if err != nil {
		if errors.Is(err, service.ErrUserNotFound) {
			writeError(w, http.StatusNotFound, "user_not_found", "No user exists for the provided user_id.", false)
			return
		}
		writeError(w, http.StatusInternalServerError, "internal_error", "Internal server error.", true)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"user_id":              result.UserID,
		"identity_key_ed25519": result.IdentityKeyEd25519,
		"dh_key_x25519":        result.DHKeyX25519,
		"keyset_version":       result.KeysetVersion,
		"updated_at":           result.UpdatedAt.Format(time.RFC3339),
	})
}

type apiError struct {
	Error struct {
		Code      string `json:"code"`
		Message   string `json:"message"`
		Retryable bool   `json:"retryable"`
	} `json:"error"`
	RequestID string `json:"request_id"`
}

func writeError(w http.ResponseWriter, status int, code, message string, retryable bool) {
	resp := apiError{RequestID: newRequestID()}
	resp.Error.Code = code
	resp.Error.Message = message
	resp.Error.Retryable = retryable
	writeJSON(w, status, resp)
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func newRequestID() string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "req_unknown"
	}
	return "req_" + hex.EncodeToString(b)
}
