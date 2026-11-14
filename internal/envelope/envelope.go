// Package envelope implements envelope encryption: data is encrypted with a
// random per-object data key (DEK), and the DEK is encrypted ("wrapped") with
// a master key (KEK) held by a KeyManager.
//
// All encryption uses AES-256-GCM from the Go standard library with a random
// 96-bit nonce. Additional authenticated data (AAD) binds every ciphertext to
// its context, so a ciphertext or wrapped key copied to another document or
// version fails authentication.
package envelope

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
)

// KeySize is the size of data and master keys in bytes (AES-256).
const KeySize = 32

// ErrDecrypt is returned when a ciphertext cannot be authenticated: wrong
// key, wrong AAD, or tampered data. The cause is deliberately not exposed.
var ErrDecrypt = errors.New("decryption failed")

// NewDataKey returns a fresh random data key.
func NewDataKey() ([]byte, error) {
	key := make([]byte, KeySize)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("generate data key: %w", err)
	}
	return key, nil
}

// Seal encrypts plaintext with key and returns nonce || ciphertext || tag.
func Seal(key, plaintext, aad []byte) ([]byte, error) {
	aead, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	out := make([]byte, aead.NonceSize(), aead.NonceSize()+len(plaintext)+aead.Overhead())
	if _, err := rand.Read(out); err != nil {
		return nil, fmt.Errorf("generate nonce: %w", err)
	}
	return aead.Seal(out, out, plaintext, aad), nil
}

// Open authenticates and decrypts a value produced by Seal.
func Open(key, sealed, aad []byte) ([]byte, error) {
	aead, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	if len(sealed) < aead.NonceSize()+aead.Overhead() {
		return nil, ErrDecrypt
	}
	nonce, ciphertext := sealed[:aead.NonceSize()], sealed[aead.NonceSize():]
	plaintext, err := aead.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return nil, ErrDecrypt
	}
	return plaintext, nil
}

func newGCM(key []byte) (cipher.AEAD, error) {
	if len(key) != KeySize {
		return nil, fmt.Errorf("invalid key size %d, want %d", len(key), KeySize)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("create cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create GCM: %w", err)
	}
	return aead, nil
}
