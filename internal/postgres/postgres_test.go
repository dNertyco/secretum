package postgres

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/dNertyco/secretum/internal/auth"
)

// testPool connects to the database from SECRETUM_TEST_DATABASE_URL, applies
// migrations and truncates all tables. The test is skipped when the variable
// is not set; CI runs these tests against a real PostgreSQL.
func testPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	url := os.Getenv("SECRETUM_TEST_DATABASE_URL")
	if url == "" {
		t.Skip("SECRETUM_TEST_DATABASE_URL is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	pool, err := Connect(ctx, url)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(pool.Close)

	if err := Migrate(ctx, pool); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	if _, err := pool.Exec(ctx, `TRUNCATE users CASCADE`); err != nil {
		t.Fatalf("truncate: %v", err)
	}
	return pool
}

func TestMigrateIsIdempotent(t *testing.T) {
	pool := testPool(t)
	if err := Migrate(t.Context(), pool); err != nil {
		t.Fatalf("second migrate: %v", err)
	}
}

func TestUsers(t *testing.T) {
	repo := NewUsers(testPool(t))
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
