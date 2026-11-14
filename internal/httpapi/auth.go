package httpapi

import (
	"context"
	"errors"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/dNertyco/secretum/internal/auth"
)

type credentials struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type userResponse struct {
	ID        uuid.UUID `json:"id"`
	Username  string    `json:"username"`
	CreatedAt time.Time `json:"created_at"`
}

func toUserResponse(u auth.User) userResponse {
	return userResponse{ID: u.ID, Username: u.Username, CreatedAt: u.CreatedAt}
}

type tokenResponse struct {
	AccessToken string    `json:"access_token"`
	TokenType   string    `json:"token_type"`
	ExpiresAt   time.Time `json:"expires_at"`
}

func (a *api) register(w http.ResponseWriter, r *http.Request) {
	if !a.AllowRegistration {
		a.writeError(w, http.StatusForbidden, "registration_disabled", "registration is disabled")
		return
	}
	if !a.LoginLimiter.Allow(clientIP(r)) {
		a.writeError(w, http.StatusTooManyRequests, "rate_limited", "too many attempts, try again later")
		return
	}
	var req credentials
	if err := decodeJSON(w, r, &req); err != nil {
		a.writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}

	u, err := a.Auth.Register(r.Context(), req.Username, req.Password)
	switch {
	case errors.Is(err, auth.ErrInvalidUsername), errors.Is(err, auth.ErrInvalidPassword):
		a.writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
	case errors.Is(err, auth.ErrUsernameTaken):
		a.writeError(w, http.StatusConflict, "username_taken", err.Error())
	case err != nil:
		a.internalError(w, r, err)
	default:
		a.writeJSON(w, http.StatusCreated, toUserResponse(u))
	}
}

func (a *api) login(w http.ResponseWriter, r *http.Request) {
	if !a.LoginLimiter.Allow(clientIP(r)) {
		a.writeError(w, http.StatusTooManyRequests, "rate_limited", "too many attempts, try again later")
		return
	}
	var req credentials
	if err := decodeJSON(w, r, &req); err != nil {
		a.writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}

	_, tok, err := a.Auth.Login(r.Context(), req.Username, req.Password)
	switch {
	case errors.Is(err, auth.ErrInvalidCredentials):
		a.writeError(w, http.StatusUnauthorized, "invalid_credentials", err.Error())
	case err != nil:
		a.internalError(w, r, err)
	default:
		a.writeJSON(w, http.StatusOK, tokenResponse{AccessToken: tok.AccessToken, TokenType: "Bearer", ExpiresAt: tok.ExpiresAt})
	}
}

func (a *api) me(w http.ResponseWriter, r *http.Request) {
	a.writeJSON(w, http.StatusOK, toUserResponse(userFrom(r.Context())))
}

type userCtxKey struct{}

func userFrom(ctx context.Context) auth.User {
	u, _ := ctx.Value(userCtxKey{}).(auth.User)
	return u
}

// authenticated requires a valid bearer token and stores the user in the
// request context.
func (a *api) authenticated(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		if !ok || token == "" {
			w.Header().Set("WWW-Authenticate", `Bearer realm="secretum"`)
			a.writeError(w, http.StatusUnauthorized, "unauthenticated", "missing bearer token")
			return
		}
		u, err := a.Auth.Authenticate(r.Context(), token)
		if errors.Is(err, auth.ErrInvalidToken) {
			w.Header().Set("WWW-Authenticate", `Bearer realm="secretum", error="invalid_token"`)
			a.writeError(w, http.StatusUnauthorized, "unauthenticated", "invalid or expired token")
			return
		}
		if err != nil {
			a.internalError(w, r, err)
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), userCtxKey{}, u)))
	})
}

// clientIP returns the address of the direct peer. Forwarded headers are
// ignored on purpose: they are client-controlled unless a trusted proxy is
// configured.
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
