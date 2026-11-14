package postgres_test

import (
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/dNertyco/secretum/internal/auth"
	"github.com/dNertyco/secretum/internal/documents"
	"github.com/dNertyco/secretum/internal/documents/doctest"
	"github.com/dNertyco/secretum/internal/postgres"
	"github.com/dNertyco/secretum/internal/postgres/pgtest"
)

func TestMigrateIsIdempotent(t *testing.T) {
	pool := pgtest.New(t)
	if err := postgres.Migrate(t.Context(), pool); err != nil {
		t.Fatalf("second migrate: %v", err)
	}
}

func TestUsers(t *testing.T) {
	repo := postgres.NewUsers(pgtest.New(t))
	ctx := t.Context()

	u := auth.User{
		ID:           uuid.Must(uuid.NewV7()),
		Username:     "alice",
		PasswordHash: "$argon2id$hash",
		CreatedAt:    time.Now().UTC().Truncate(time.Microsecond),
	}
	if err := repo.CreateUser(ctx, u); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	dup := u
	dup.ID = uuid.Must(uuid.NewV7())
	if err := repo.CreateUser(ctx, dup); !errors.Is(err, auth.ErrUsernameTaken) {
		t.Errorf("duplicate username: err = %v, want %v", err, auth.ErrUsernameTaken)
	}

	byName, err := repo.UserByUsername(ctx, "alice")
	if err != nil || byName.ID != u.ID || !byName.CreatedAt.Equal(u.CreatedAt) {
		t.Errorf("UserByUsername = %+v, %v", byName, err)
	}
	byID, err := repo.UserByID(ctx, u.ID)
	if err != nil || byID.Username != "alice" {
		t.Errorf("UserByID = %+v, %v", byID, err)
	}

	if _, err := repo.UserByUsername(ctx, "nobody"); !errors.Is(err, auth.ErrUserNotFound) {
		t.Errorf("unknown username: err = %v", err)
	}
	if _, err := repo.UserByID(ctx, uuid.New()); !errors.Is(err, auth.ErrUserNotFound) {
		t.Errorf("unknown id: err = %v", err)
	}
}

func TestDocumentsContract(t *testing.T) {
	doctest.RunRepositoryContract(t, func(t *testing.T) (documents.Repository, auth.UserRepository) {
		pool := pgtest.New(t)
		return postgres.NewDocuments(pool), postgres.NewUsers(pool)
	})
}
