// Package auth implements user registration, password authentication and
// access tokens.
package auth

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
)

const (
	minPasswordLen = 12
	maxPasswordLen = 256
)

var usernamePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{2,31}$`)

// Errors returned by Service.
var (
	ErrInvalidUsername    = errors.New("username must be 3-32 characters: lowercase letters, digits, '.', '_', '-'")
	ErrInvalidPassword    = fmt.Errorf("password must be %d-%d characters", minPasswordLen, maxPasswordLen)
	ErrUsernameTaken      = errors.New("username is already taken")
	ErrInvalidCredentials = errors.New("invalid username or password")
	ErrUserNotFound       = errors.New("user not found")
)

// User is a registered account.
type User struct {
	ID           uuid.UUID
	Username     string
	PasswordHash string
	CreatedAt    time.Time
}

// UserRepository persists users.
type UserRepository interface {
	// CreateUser stores a new user or returns ErrUsernameTaken.
	CreateUser(ctx context.Context, u User) error
	// UserByUsername returns ErrUserNotFound if there is no such user.
	UserByUsername(ctx context.Context, username string) (User, error)
	// UserByID returns ErrUserNotFound if there is no such user.
	UserByID(ctx context.Context, id uuid.UUID) (User, error)
}

// Token is an issued access token.
type Token struct {
	AccessToken string
	ExpiresAt   time.Time
}

// Service registers and authenticates users.
type Service struct {
	users  UserRepository
	tokens *TokenIssuer
	now    func() time.Time

	// dummyHash is verified when a user does not exist, so that login takes
	// the same time whether or not the username is registered.
	dummyHash string
}

// NewService returns an authentication service.
func NewService(users UserRepository, tokens *TokenIssuer) (*Service, error) {
	dummy, err := HashPassword("dummy-password-for-timing")
	if err != nil {
		return nil, err
	}
	return &Service{users: users, tokens: tokens, now: time.Now, dummyHash: dummy}, nil
}

// NormalizeUsername trims and lower-cases a username.
func NormalizeUsername(username string) string {
	return strings.ToLower(strings.TrimSpace(username))
}

// Register creates a user account.
func (s *Service) Register(ctx context.Context, username, password string) (User, error) {
	username = NormalizeUsername(username)
	if !usernamePattern.MatchString(username) {
		return User{}, ErrInvalidUsername
	}
	if n := utf8.RuneCountInString(password); n < minPasswordLen || n > maxPasswordLen {
		return User{}, ErrInvalidPassword
	}

	hash, err := HashPassword(password)
	if err != nil {
		return User{}, err
	}
	id, err := uuid.NewV7()
	if err != nil {
		return User{}, fmt.Errorf("generate user id: %w", err)
	}
	u := User{ID: id, Username: username, PasswordHash: hash, CreatedAt: s.now().UTC()}
	if err := s.users.CreateUser(ctx, u); err != nil {
		return User{}, err
	}
	return u, nil
}

// Login verifies credentials and issues an access token.
func (s *Service) Login(ctx context.Context, username, password string) (User, Token, error) {
	if len(password) > maxPasswordLen*4 {
		return User{}, Token{}, ErrInvalidCredentials
	}

	u, err := s.users.UserByUsername(ctx, NormalizeUsername(username))
	switch {
	case errors.Is(err, ErrUserNotFound):
		_, _ = VerifyPassword(password, s.dummyHash)
		return User{}, Token{}, ErrInvalidCredentials
	case err != nil:
		return User{}, Token{}, err
	}

	ok, err := VerifyPassword(password, u.PasswordHash)
	if err != nil {
		return User{}, Token{}, fmt.Errorf("verify password: %w", err)
	}
	if !ok {
		return User{}, Token{}, ErrInvalidCredentials
	}

	access, exp, err := s.tokens.Issue(u.ID)
	if err != nil {
		return User{}, Token{}, err
	}
	return u, Token{AccessToken: access, ExpiresAt: exp}, nil
}

// Authenticate verifies an access token and returns its user.
func (s *Service) Authenticate(ctx context.Context, token string) (User, error) {
	id, err := s.tokens.Verify(token)
	if err != nil {
		return User{}, err
	}
	u, err := s.users.UserByID(ctx, id)
	if errors.Is(err, ErrUserNotFound) {
		return User{}, ErrInvalidToken
	}
	return u, err
}
