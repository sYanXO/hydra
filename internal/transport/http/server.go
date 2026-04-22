package httptransport

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strconv"
	"time"

	"hydra/internal/protocol"
	"hydra/internal/service"
)

type Server struct {
	registerService *service.RegisterService
	messageService  *service.MessageService
	mux             *http.ServeMux
}

func NewServer(registerService *service.RegisterService, messageService *service.MessageService) *Server {
	s := &Server{registerService: registerService, messageService: messageService, mux: http.NewServeMux()}
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
	s.mux.HandleFunc("GET /users/by-handle/{username}/{discriminator}/keys", s.handleGetUserKeysByHandle)
	s.mux.HandleFunc("POST /messages", s.handlePostMessage)
	s.mux.HandleFunc("GET /messages/poll", s.handlePollMessages)
	s.mux.HandleFunc("POST /messages/ack", s.handleAckMessages)
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
		case errors.Is(err, service.ErrInvalidUsername):
			writeError(w, http.StatusBadRequest, "invalid_username", "requested_username is invalid.", false)
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
		"handle": map[string]any{
			"username":      result.Handle.UsernameNorm,
			"discriminator": result.Handle.Discriminator,
			"full":          result.Handle.Full(),
		},
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
		"handle": map[string]any{
			"username":      result.Handle.UsernameNorm,
			"discriminator": result.Handle.Discriminator,
			"full":          result.Handle.Full(),
		},
	})
}

func (s *Server) handleGetUserKeysByHandle(w http.ResponseWriter, r *http.Request) {
	username := r.PathValue("username")
	discriminator := r.PathValue("discriminator")
	if username == "" || discriminator == "" {
		writeError(w, http.StatusBadRequest, "bad_request", "Missing username or discriminator.", false)
		return
	}
	result, err := s.registerService.GetUserKeysByHandle(username, discriminator)
	if err != nil {
		switch {
		case errors.Is(err, service.ErrInvalidUsername):
			writeError(w, http.StatusBadRequest, "invalid_username", "Invalid username or discriminator.", false)
		case errors.Is(err, service.ErrUserNotFound):
			writeError(w, http.StatusNotFound, "user_not_found", "No user exists for the provided handle.", false)
		default:
			writeError(w, http.StatusInternalServerError, "internal_error", "Internal server error.", true)
		}
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"user_id":              result.UserID,
		"identity_key_ed25519": result.IdentityKeyEd25519,
		"dh_key_x25519":        result.DHKeyX25519,
		"keyset_version":       result.KeysetVersion,
		"updated_at":           result.UpdatedAt.Format(time.RFC3339),
		"handle": map[string]any{
			"username":      result.Handle.UsernameNorm,
			"discriminator": result.Handle.Discriminator,
			"full":          result.Handle.Full(),
		},
	})
}

func (s *Server) handlePostMessage(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	var req protocol.MessageEnvelope
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", "Malformed JSON.", false)
		return
	}
	result, err := s.messageService.SendMessage(req)
	if err != nil {
		switch {
		case errors.Is(err, protocol.ErrInvalidEnvelope):
			writeError(w, http.StatusBadRequest, "invalid_envelope", "Envelope validation failed.", false)
		case errors.Is(err, protocol.ErrRecipientNotFound):
			writeError(w, http.StatusNotFound, "recipient_not_found", "Recipient does not exist.", false)
		case errors.Is(err, protocol.ErrDuplicateMessage):
			writeError(w, http.StatusConflict, "duplicate_message_id", "Duplicate message_id for sender-recipient pair.", false)
		default:
			writeError(w, http.StatusInternalServerError, "internal_error", "Internal server error.", true)
		}
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"ok":                true,
		"server_message_id": result.ServerMessageID,
		"received_at":       result.ReceivedAt.Format(time.RFC3339),
	})
}

func (s *Server) handlePollMessages(w http.ResponseWriter, r *http.Request) {
	userID := r.URL.Query().Get("user_id")
	limit := 50
	if raw := r.URL.Query().Get("limit"); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil {
			writeError(w, http.StatusBadRequest, "bad_request", "Invalid limit.", false)
			return
		}
		limit = parsed
	}
	messages, err := s.messageService.PollMessages(userID, limit)
	if err != nil {
		switch {
		case errors.Is(err, service.ErrBadRequest):
			writeError(w, http.StatusBadRequest, "bad_request", "Invalid poll request.", false)
		case errors.Is(err, service.ErrUserNotFound):
			writeError(w, http.StatusNotFound, "user_not_found", "No user exists for the provided user_id.", false)
		default:
			writeError(w, http.StatusInternalServerError, "internal_error", "Internal server error.", true)
		}
		return
	}
	items := make([]map[string]any, 0, len(messages))
	for _, m := range messages {
		items = append(items, map[string]any{
			"server_message_id": m.ServerMessageID,
			"from_user_id":      m.FromUserID,
			"received_at":       m.ReceivedAt.Format(time.RFC3339),
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"messages": items})
}

type ackRequest struct {
	UserID           string   `json:"user_id"`
	ServerMessageIDs []string `json:"server_message_ids"`
	AckedAt          string   `json:"acked_at"`
}

func (s *Server) handleAckMessages(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	var req ackRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", "Malformed JSON.", false)
		return
	}
	ackedAt, err := time.Parse(time.RFC3339, req.AckedAt)
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", "Invalid acked_at.", false)
		return
	}
	res, err := s.messageService.AckMessages(req.UserID, req.ServerMessageIDs, ackedAt)
	if err != nil {
		switch {
		case errors.Is(err, service.ErrBadRequest):
			writeError(w, http.StatusBadRequest, "bad_request", "Invalid ack request.", false)
		case errors.Is(err, service.ErrUserNotFound):
			writeError(w, http.StatusNotFound, "user_not_found", "No user exists for the provided user_id.", false)
		default:
			reqID := newRequestID()
			log.Printf("request_id=%s route=POST /messages/ack user_id=%s server_message_ids=%d error=%v", reqID, req.UserID, len(req.ServerMessageIDs), err)
			writeErrorWithRequestID(w, http.StatusInternalServerError, "internal_error", "Internal server error.", true, reqID)
		}
		return
	}
	items := make([]map[string]any, 0, len(res.Messages))
	for _, m := range res.Messages {
		items = append(items, map[string]any{
			"server_message_id": m.ServerMessageID,
			"envelope":          m.Envelope,
			"received_at":       m.ReceivedAt.Format(time.RFC3339),
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":          true,
		"acked_count": res.AckedCount,
		"acked_at":    res.AckedAt.Format(time.RFC3339),
		"messages":    items,
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
	writeErrorWithRequestID(w, status, code, message, retryable, newRequestID())
}

func writeErrorWithRequestID(w http.ResponseWriter, status int, code, message string, retryable bool, requestID string) {
	resp := apiError{RequestID: requestID}
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
