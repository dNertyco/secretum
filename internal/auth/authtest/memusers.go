// Package authtest provides test doubles for the auth package.
package authtest

import (
	"context"
	"sync"

	"github.com/google/uuid"

	"github.com/dNertyco/secretum/internal/auth"
)

// MemUsers is an in-memory auth.UserRepository for tests.
type MemUsers struct {
	mu    sync.Mutex
	users map[uuid.UUID]auth.User
}

// NewMemUsers returns an empty in-memory user repository.
func NewMemUsers() *MemUsers {
	return &MemUsers{users: make(map[uuid.UUID]auth.User)}
}

var _ auth.UserRepository = (*MemUsers)(nil)

// CreateUser implements auth.UserRepository.
func (m *MemUsers) CreateUser(_ context.Context, u auth.User) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, existing := range m.users {
		if existing.Username == u.Username {
			return auth.ErrUsernameTaken
		}
	}
	m.users[u.ID] = u
	return nil
}

// UserByUsername implements auth.UserRepository.
func (m *MemUsers) UserByUsername(_ context.Context, username string) (auth.User, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, u := range m.users {
		if u.Username == username {
			return u, nil
		}
	}
	return auth.User{}, auth.ErrUserNotFound
}

// UserByID implements auth.UserRepository.
func (m *MemUsers) UserByID(_ context.Context, id uuid.UUID) (auth.User, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	u, ok := m.users[id]
	if !ok {
		return auth.User{}, auth.ErrUserNotFound
	}
	return u, nil
}
