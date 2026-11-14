package blob

import (
	"bytes"
	"errors"
	"os"
	"testing"

	"github.com/google/uuid"
)

func testStore(t *testing.T, s Store) {
	t.Helper()
	ctx := t.Context()
	key := "test/" + uuid.NewString()

	if err := s.Ping(ctx); err != nil {
		t.Fatalf("Ping: %v", err)
	}
	if _, err := s.Get(ctx, key); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Get missing: err = %v, want %v", err, ErrNotFound)
	}
	if err := s.Put(ctx, key, []byte("ciphertext")); err != nil {
		t.Fatalf("Put: %v", err)
	}
	got, err := s.Get(ctx, key)
	if err != nil || !bytes.Equal(got, []byte("ciphertext")) {
		t.Fatalf("Get = %q, %v", got, err)
	}
	if err := s.Delete(ctx, key); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := s.Get(ctx, key); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Get after delete: err = %v, want %v", err, ErrNotFound)
	}
	if err := s.Delete(ctx, key); err != nil {
		t.Fatalf("Delete missing: %v", err)
	}
}

func TestMemory(t *testing.T) {
	testStore(t, NewMemory())
}

// TestS3 runs against an S3-compatible service when SECRETUM_TEST_S3_ENDPOINT
// is set (CI starts MinIO for it).
func TestS3(t *testing.T) {
	endpoint := os.Getenv("SECRETUM_TEST_S3_ENDPOINT")
	if endpoint == "" {
		t.Skip("SECRETUM_TEST_S3_ENDPOINT is not set")
	}
	s, err := NewS3(t.Context(), S3Config{
		Endpoint:  endpoint,
		AccessKey: os.Getenv("SECRETUM_TEST_S3_ACCESS_KEY"),
		SecretKey: os.Getenv("SECRETUM_TEST_S3_SECRET_KEY"),
		Bucket:    "secretum-test",
	})
	if err != nil {
		t.Fatalf("NewS3: %v", err)
	}
	testStore(t, s)
}
