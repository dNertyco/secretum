package auth

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
)

type memUsers struct {
	mu    sync.Mutex
	users map[uuid.UUID]User
}

func newMemUsers() *memUsers { return &memUsers{users: map[uuid.UUID]User{}} }

func (m *memUsers) CreateUser(_ context.Context, u User) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, existing := range m.users {
		if existing.Username == u.Username {
			return ErrUsernameTaken
		}
	}
	m.users[u.ID] = u
	return nil
}

func (m *memUsers) UserByUsername(_ context.Context, username string) (User, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, u := range m.users {
		if u.Username == username {
			return u, nil
		}
	}
	return User{}, ErrUserNotFound
}

func (m *memUsers) UserByID(_ context.Context, id uuid.UUID) (User, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	u, ok := m.users[id]
	if !ok {
		return User{}, ErrUserNotFound
	}
	return u, nil
}

var testSecret = []byte("0123456789abcdef0123456789abcdef")

func newTestService(t *testing.T) (*Service, *memUsers) {
	t.Helper()
	repo := newMemUsers()
	svc, err := NewService(repo, NewTokenIssuer(testSecret, time.Minute))
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	return svc, repo
}

func TestPasswordHashRoundTrip(t *testing.T) {
	hash, err := HashPassword("correct horse battery staple")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	if !strings.HasPrefix(hash, "$argon2id$v=19$m=19456,t=2,p=1$") {
		t.Errorf("unexpected hash format: %s", hash)
	}

	ok, err := VerifyPassword("correct horse battery staple", hash)
	if err != nil || !ok {
		t.Errorf("VerifyPassword(correct) = %v, %v; want true, nil", ok, err)
	}
	ok, err = VerifyPassword("wrong password", hash)
	if err != nil || ok {
		t.Errorf("VerifyPassword(wrong) = %v, %v; want false, nil", ok, err)
	}
}

func TestPasswordHashesAreSalted(t *testing.T) {
	a, _ := HashPassword("same password")
	b, _ := HashPassword("same password")
	if a == b {
		t.Error("two hashes of the same password are equal; salt is not random")
	}
}

func TestVerifyPasswordMalformed(t *testing.T) {
	for _, h := range []string{"", "plain", "$argon2i$v=19$m=1,t=1,p=1$c2FsdA$a2V5", "$argon2id$v=19$m=x$c2FsdA$a2V5"} {
		if _, err := VerifyPassword("x", h); err == nil {
			t.Errorf("VerifyPassword(%q): expected error", h)
		}
	}
}

func TestTokenRoundTrip(t *testing.T) {
	issuer := NewTokenIssuer(testSecret, time.Minute)
	id := uuid.New()

	token, exp, err := issuer.Issue(id)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if time.Until(exp) <= 0 {
		t.Errorf("expiry %v is not in the future", exp)
	}
	got, err := issuer.Verify(token)
	if err != nil || got != id {
		t.Errorf("Verify = %v, %v; want %v, nil", got, err, id)
	}
}

func TestTokenRejected(t *testing.T) {
	issuer := NewTokenIssuer(testSecret, time.Minute)
	token, _, _ := issuer.Issue(uuid.New())

	other := NewTokenIssuer([]byte("another-secret-another-secret-xx"), time.Minute)
	if _, err := other.Verify(token); !errors.Is(err, ErrInvalidToken) {
		t.Errorf("token signed with another secret: err = %v", err)
	}

	expired := NewTokenIssuer(testSecret, time.Minute)
	expired.now = func() time.Time { return time.Now().Add(2 * time.Minute) }
	if _, err := expired.Verify(token); !errors.Is(err, ErrInvalidToken) {
		t.Errorf("expired token: err = %v", err)
	}

	// "alg: none" token with the same claims must never be accepted.
	parts := strings.Split(token, ".")
	none := "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0." + parts[1] + "."
	if _, err := issuer.Verify(none); !errors.Is(err, ErrInvalidToken) {
		t.Errorf("alg=none token: err = %v", err)
	}

	if _, err := issuer.Verify("garbage"); !errors.Is(err, ErrInvalidToken) {
		t.Errorf("garbage token: err = %v", err)
	}
}

func TestRegisterAndLogin(t *testing.T) {
	svc, _ := newTestService(t)
	ctx := t.Context()

	u, err := svc.Register(ctx, "  Alice.Smith ", "a-long-enough-password")
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	if u.Username != "alice.smith" {
		t.Errorf("username not normalized: %q", u.Username)
	}
	if u.ID.Version() != 7 {
		t.Errorf("user id version = %d, want 7", u.ID.Version())
	}

	got, tok, err := svc.Login(ctx, "ALICE.SMITH", "a-long-enough-password")
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	if got.ID != u.ID || tok.AccessToken == "" {
		t.Errorf("Login returned %+v, %+v", got, tok)
	}

	authed, err := svc.Authenticate(ctx, tok.AccessToken)
	if err != nil || authed.ID != u.ID {
		t.Errorf("Authenticate = %+v, %v", authed, err)
	}
}

func TestRegisterValidation(t *testing.T) {
	svc, _ := newTestService(t)
	ctx := t.Context()

	tests := []struct {
		name, username, password string
		want                     error
	}{
		{"short username", "ab", "a-long-enough-password", ErrInvalidUsername},
		{"bad characters", "al ice", "a-long-enough-password", ErrInvalidUsername},
		{"short password", "alice", "short", ErrInvalidPassword},
		{"long password", "alice", strings.Repeat("x", maxPasswordLen+1), ErrInvalidPassword},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := svc.Register(ctx, tt.username, tt.password); !errors.Is(err, tt.want) {
				t.Errorf("err = %v, want %v", err, tt.want)
			}
		})
	}

	if _, err := svc.Register(ctx, "bob", "a-long-enough-password"); err != nil {
		t.Fatalf("Register: %v", err)
	}
	if _, err := svc.Register(ctx, "BOB", "another-long-password"); !errors.Is(err, ErrUsernameTaken) {
		t.Errorf("duplicate username: err = %v, want %v", err, ErrUsernameTaken)
	}
}

func TestLoginFailures(t *testing.T) {
	svc, _ := newTestService(t)
	ctx := t.Context()
	if _, err := svc.Register(ctx, "carol", "a-long-enough-password"); err != nil {
		t.Fatalf("Register: %v", err)
	}

	if _, _, err := svc.Login(ctx, "carol", "wrong-password-123"); !errors.Is(err, ErrInvalidCredentials) {
		t.Errorf("wrong password: err = %v", err)
	}
	if _, _, err := svc.Login(ctx, "nobody", "a-long-enough-password"); !errors.Is(err, ErrInvalidCredentials) {
		t.Errorf("unknown user: err = %v", err)
	}
}

func TestAuthenticateDeletedUser(t *testing.T) {
	svc, repo := newTestService(t)
	ctx := t.Context()
	u, _ := svc.Register(ctx, "dave", "a-long-enough-password")
	_, tok, _ := svc.Login(ctx, "dave", "a-long-enough-password")

	repo.mu.Lock()
	delete(repo.users, u.ID)
	repo.mu.Unlock()

	if _, err := svc.Authenticate(ctx, tok.AccessToken); !errors.Is(err, ErrInvalidToken) {
		t.Errorf("err = %v, want %v", err, ErrInvalidToken)
	}
}
