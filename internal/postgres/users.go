package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/dNertyco/secretum/internal/auth"
)

// Users is a PostgreSQL-backed auth.UserRepository.
type Users struct {
	pool *pgxpool.Pool
}

// NewUsers returns a user repository.
func NewUsers(pool *pgxpool.Pool) *Users {
	return &Users{pool: pool}
}

var _ auth.UserRepository = (*Users)(nil)

// CreateUser implements auth.UserRepository.
func (r *Users) CreateUser(ctx context.Context, u auth.User) error {
	_, err := r.pool.Exec(ctx,
		`INSERT INTO users (id, username, password_hash, created_at) VALUES ($1, $2, $3, $4)`,
		u.ID, u.Username, u.PasswordHash, u.CreatedAt)
	if isUniqueViolation(err) {
		return auth.ErrUsernameTaken
	}
	if err != nil {
		return fmt.Errorf("insert user: %w", err)
	}
	return nil
}

// UserByUsername implements auth.UserRepository.
func (r *Users) UserByUsername(ctx context.Context, username string) (auth.User, error) {
	return r.one(ctx, `SELECT id, username, password_hash, created_at FROM users WHERE username = $1`, username)
}

// UserByID implements auth.UserRepository.
func (r *Users) UserByID(ctx context.Context, id uuid.UUID) (auth.User, error) {
	return r.one(ctx, `SELECT id, username, password_hash, created_at FROM users WHERE id = $1`, id)
}

func (r *Users) one(ctx context.Context, query string, arg any) (auth.User, error) {
	var u auth.User
	err := r.pool.QueryRow(ctx, query, arg).Scan(&u.ID, &u.Username, &u.PasswordHash, &u.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return auth.User{}, auth.ErrUserNotFound
	}
	if err != nil {
		return auth.User{}, fmt.Errorf("select user: %w", err)
	}
	return u, nil
}
