package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/dNertyco/secretum/internal/auth"
	"github.com/dNertyco/secretum/internal/auth/authtest"
	"github.com/dNertyco/secretum/internal/blob"
	"github.com/dNertyco/secretum/internal/documents"
	"github.com/dNertyco/secretum/internal/documents/doctest"
	"github.com/dNertyco/secretum/internal/envelope"
	"github.com/dNertyco/secretum/internal/ratelimit"
)

type testServer struct {
	t       *testing.T
	handler http.Handler
	blobs   *blob.Memory
}

func newTestServer(t *testing.T, mutate ...func(*Deps)) *testServer {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	users := authtest.NewMemUsers()
	svc, err := auth.NewService(users,
		auth.NewTokenIssuer([]byte("0123456789abcdef0123456789abcdef"), time.Minute))
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	kek, _ := envelope.NewDataKey()
	keys, err := envelope.NewLocalKeyManager(map[string][]byte{"k1": kek}, "k1")
	if err != nil {
		t.Fatalf("NewLocalKeyManager: %v", err)
	}
	blobs := blob.NewMemory()
	d := Deps{
		Logger:            logger,
		Build:             BuildInfo{Version: "test", Commit: "abc123"},
		Auth:              svc,
		Documents:         documents.NewService(doctest.NewMemRepo(users), blobs, keys, users, logger),
		MaxUploadBytes:    1 << 10,
		LoginLimiter:      ratelimit.New(600, 100),
		AllowRegistration: true,
		Readiness:         map[string]ReadinessCheck{"db": func(context.Context) error { return nil }},
	}
	for _, m := range mutate {
		m(&d)
	}
	return &testServer{t: t, handler: NewRouter(d), blobs: blobs}
}

func (s *testServer) do(method, path string, body any, token string) *httptest.ResponseRecorder {
	s.t.Helper()
	var r io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			s.t.Fatalf("marshal: %v", err)
		}
		r = bytes.NewReader(b)
	}
	req := httptest.NewRequestWithContext(s.t.Context(), method, path, r)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	s.handler.ServeHTTP(rec, req)
	return rec
}

func decode[T any](t *testing.T, rec *httptest.ResponseRecorder) T {
	t.Helper()
	var v T
	if err := json.NewDecoder(rec.Body).Decode(&v); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	return v
}

func assertError(t *testing.T, rec *httptest.ResponseRecorder, status int, code string) {
	t.Helper()
	if rec.Code != status {
		t.Fatalf("status = %d, want %d; body: %s", rec.Code, status, rec.Body)
	}
	if got := decode[errorBody](t, rec).Error.Code; got != code {
		t.Errorf("error code = %q, want %q", got, code)
	}
}

func TestHealthz(t *testing.T) {
	rec := newTestServer(t).do(http.MethodGet, "/healthz", nil, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	if got := decode[map[string]string](t, rec)["status"]; got != "ok" {
		t.Errorf("status field = %q", got)
	}
}

func TestReadyz(t *testing.T) {
	rec := newTestServer(t).do(http.MethodGet, "/readyz", nil, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}

	down := newTestServer(t, func(d *Deps) {
		d.Readiness["db"] = func(context.Context) error { return errors.New("connection refused") }
	})
	rec = down.do(http.MethodGet, "/readyz", nil, "")
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusServiceUnavailable)
	}
	body := decode[map[string]map[string]string](t, rec)
	if body["checks"]["db"] != "unavailable" {
		t.Errorf("checks = %v", body["checks"])
	}
}

func TestVersion(t *testing.T) {
	got := decode[BuildInfo](t, newTestServer(t).do(http.MethodGet, "/version", nil, ""))
	if got.Version != "test" || got.Commit != "abc123" {
		t.Errorf("got %+v", got)
	}
}

func TestMethodNotAllowed(t *testing.T) {
	rec := newTestServer(t).do(http.MethodPost, "/healthz", nil, "")
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusMethodNotAllowed)
	}
}

func TestRegisterLoginMe(t *testing.T) {
	s := newTestServer(t)
	creds := credentials{Username: "alice", Password: "a-long-enough-password"}

	rec := s.do(http.MethodPost, "/v1/auth/register", creds, "")
	if rec.Code != http.StatusCreated {
		t.Fatalf("register status = %d; body: %s", rec.Code, rec.Body)
	}
	user := decode[userResponse](t, rec)

	rec = s.do(http.MethodPost, "/v1/auth/login", creds, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("login status = %d; body: %s", rec.Code, rec.Body)
	}
	tok := decode[tokenResponse](t, rec)
	if tok.TokenType != "Bearer" || tok.AccessToken == "" {
		t.Fatalf("unexpected token response: %+v", tok)
	}

	rec = s.do(http.MethodGet, "/v1/me", nil, tok.AccessToken)
	if rec.Code != http.StatusOK {
		t.Fatalf("me status = %d", rec.Code)
	}
	if me := decode[userResponse](t, rec); me.ID != user.ID || me.Username != "alice" {
		t.Errorf("me = %+v, want %+v", me, user)
	}
}

func TestRegisterErrors(t *testing.T) {
	s := newTestServer(t)
	creds := credentials{Username: "bob", Password: "a-long-enough-password"}
	s.do(http.MethodPost, "/v1/auth/register", creds, "")

	assertError(t, s.do(http.MethodPost, "/v1/auth/register", creds, ""), http.StatusConflict, "username_taken")
	assertError(t, s.do(http.MethodPost, "/v1/auth/register",
		credentials{Username: "x", Password: "a-long-enough-password"}, ""), http.StatusBadRequest, "invalid_request")
	assertError(t, s.do(http.MethodPost, "/v1/auth/register",
		map[string]string{"username": "carol", "password": "a-long-enough-password", "role": "admin"}, ""),
		http.StatusBadRequest, "invalid_request")

	disabled := newTestServer(t, func(d *Deps) { d.AllowRegistration = false })
	assertError(t, disabled.do(http.MethodPost, "/v1/auth/register", creds, ""), http.StatusForbidden, "registration_disabled")
}

func TestLoginInvalidCredentials(t *testing.T) {
	s := newTestServer(t)
	s.do(http.MethodPost, "/v1/auth/register", credentials{Username: "dave", Password: "a-long-enough-password"}, "")

	assertError(t, s.do(http.MethodPost, "/v1/auth/login",
		credentials{Username: "dave", Password: "wrong-password-123"}, ""), http.StatusUnauthorized, "invalid_credentials")
	assertError(t, s.do(http.MethodPost, "/v1/auth/login",
		credentials{Username: "nobody", Password: "a-long-enough-password"}, ""), http.StatusUnauthorized, "invalid_credentials")
}

func TestLoginRateLimited(t *testing.T) {
	s := newTestServer(t, func(d *Deps) { d.LoginLimiter = ratelimit.New(1, 2) })
	creds := credentials{Username: "eve", Password: "wrong-password-123"}

	for range 2 {
		s.do(http.MethodPost, "/v1/auth/login", creds, "")
	}
	assertError(t, s.do(http.MethodPost, "/v1/auth/login", creds, ""), http.StatusTooManyRequests, "rate_limited")
}

func TestAuthenticationRequired(t *testing.T) {
	s := newTestServer(t)

	rec := s.do(http.MethodGet, "/v1/me", nil, "")
	assertError(t, rec, http.StatusUnauthorized, "unauthenticated")
	if rec.Header().Get("WWW-Authenticate") == "" {
		t.Error("missing WWW-Authenticate header")
	}
	assertError(t, s.do(http.MethodGet, "/v1/me", nil, "not-a-token"), http.StatusUnauthorized, "unauthenticated")
}

func TestRequestIDGeneratedAndPropagated(t *testing.T) {
	s := newTestServer(t)

	rec := s.do(http.MethodGet, "/healthz", nil, "")
	if id := rec.Header().Get(requestIDHeader); len(id) != 32 {
		t.Errorf("generated request ID = %q, want 32 hex chars", id)
	}

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/healthz", nil)
	req.Header.Set(requestIDHeader, "client-id-1")
	rec = httptest.NewRecorder()
	s.handler.ServeHTTP(rec, req)
	if id := rec.Header().Get(requestIDHeader); id != "client-id-1" {
		t.Errorf("propagated request ID = %q, want %q", id, "client-id-1")
	}
}

func TestRecovererReturns500(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	h := recoverer(logger, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		panic("boom")
	}))

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusInternalServerError)
	}
}
