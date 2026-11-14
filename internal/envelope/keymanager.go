package envelope

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
)

// WrappedKey is a data key encrypted with a master key.
type WrappedKey struct {
	// KEKID identifies the master key that wrapped the data key.
	KEKID string
	// Ciphertext is the sealed data key.
	Ciphertext []byte
}

// KeyManager wraps and unwraps data keys with master keys it never reveals.
//
// LocalKeyManager keeps master keys in process memory. In production the
// same interface is implemented by an external KMS, so that master keys
// never reside on the application host.
type KeyManager interface {
	// Wrap encrypts dek with the active master key.
	Wrap(ctx context.Context, dek, aad []byte) (WrappedKey, error)
	// Unwrap decrypts a wrapped key with the master key it names.
	Unwrap(ctx context.Context, wk WrappedKey, aad []byte) ([]byte, error)
}

// ErrUnknownKEK is returned when a wrapped key names a master key the
// manager does not have.
var ErrUnknownKEK = errors.New("unknown master key")

// LocalKeyManager is a KeyManager with master keys held in memory.
//
// It may hold several keys: new data keys are always wrapped with the active
// one, while older keys remain available for unwrapping. This allows master
// key rotation without re-encrypting documents: only data keys are re-wrapped.
type LocalKeyManager struct {
	keys   map[string][]byte
	active string
}

var _ KeyManager = (*LocalKeyManager)(nil)

// NewLocalKeyManager returns a key manager with the given master keys.
// active must be one of the keys.
func NewLocalKeyManager(keys map[string][]byte, active string) (*LocalKeyManager, error) {
	if len(keys) == 0 {
		return nil, errors.New("no master keys configured")
	}
	for id, k := range keys {
		if id == "" || strings.ContainsAny(id, ":,") {
			return nil, fmt.Errorf("invalid master key id %q", id)
		}
		if len(k) != KeySize {
			return nil, fmt.Errorf("master key %q: size %d, want %d", id, len(k), KeySize)
		}
	}
	if _, ok := keys[active]; !ok {
		return nil, fmt.Errorf("active master key %q is not configured (have %v)", active, slices.Sorted(maps.Keys(keys)))
	}
	return &LocalKeyManager{keys: maps.Clone(keys), active: active}, nil
}

// ParseMasterKeys parses "id1:base64key1,id2:base64key2".
func ParseMasterKeys(s string) (map[string][]byte, error) {
	keys := make(map[string][]byte)
	for item := range strings.SplitSeq(s, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		id, encoded, ok := strings.Cut(item, ":")
		if !ok || id == "" {
			return nil, errors.New("master keys must be formatted as id:base64key")
		}
		key, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			return nil, fmt.Errorf("master key %q: invalid base64", id)
		}
		if _, dup := keys[id]; dup {
			return nil, fmt.Errorf("master key %q defined twice", id)
		}
		keys[id] = key
	}
	return keys, nil
}

// ActiveKEKID returns the ID of the master key used for new data keys.
func (m *LocalKeyManager) ActiveKEKID() string { return m.active }

// Wrap implements KeyManager.
func (m *LocalKeyManager) Wrap(_ context.Context, dek, aad []byte) (WrappedKey, error) {
	sealed, err := Seal(m.keys[m.active], dek, aad)
	if err != nil {
		return WrappedKey{}, fmt.Errorf("wrap data key: %w", err)
	}
	return WrappedKey{KEKID: m.active, Ciphertext: sealed}, nil
}

// Unwrap implements KeyManager.
func (m *LocalKeyManager) Unwrap(_ context.Context, wk WrappedKey, aad []byte) ([]byte, error) {
	kek, ok := m.keys[wk.KEKID]
	if !ok {
		return nil, fmt.Errorf("%w: %q", ErrUnknownKEK, wk.KEKID)
	}
	return Open(kek, wk.Ciphertext, aad)
}
