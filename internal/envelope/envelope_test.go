package envelope

import (
	"bytes"
	"encoding/base64"
	"errors"
	"testing"
)

func mustKey(t *testing.T) []byte {
	t.Helper()
	k, err := NewDataKey()
	if err != nil {
		t.Fatalf("NewDataKey: %v", err)
	}
	return k
}

func TestSealOpenRoundTrip(t *testing.T) {
	key := mustKey(t)
	plaintext := []byte("service report No. 123")
	aad := []byte("doc:1:v1")

	sealed, err := Seal(key, plaintext, aad)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if bytes.Contains(sealed, plaintext) {
		t.Fatal("ciphertext contains plaintext")
	}
	got, err := Open(key, sealed, aad)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Errorf("Open = %q, want %q", got, plaintext)
	}
}

func TestSealUsesFreshNonce(t *testing.T) {
	key := mustKey(t)
	a, _ := Seal(key, []byte("same"), nil)
	b, _ := Seal(key, []byte("same"), nil)
	if bytes.Equal(a, b) {
		t.Fatal("two encryptions of the same plaintext are identical; nonce is reused")
	}
}

func TestOpenRejects(t *testing.T) {
	key := mustKey(t)
	aad := []byte("doc:1:v1")
	sealed, _ := Seal(key, []byte("secret"), aad)

	tampered := bytes.Clone(sealed)
	tampered[len(tampered)-1] ^= 0x01

	tests := map[string]struct {
		key, sealed, aad []byte
	}{
		"wrong key":   {mustKey(t), sealed, aad},
		"wrong aad":   {key, sealed, []byte("doc:2:v1")},
		"tampered":    {key, tampered, aad},
		"truncated":   {key, sealed[:10], aad},
		"empty":       {key, nil, aad},
		"missing aad": {key, sealed, nil},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := Open(tt.key, tt.sealed, tt.aad); !errors.Is(err, ErrDecrypt) {
				t.Errorf("err = %v, want %v", err, ErrDecrypt)
			}
		})
	}
}

func TestInvalidKeySize(t *testing.T) {
	if _, err := Seal([]byte("short"), []byte("x"), nil); err == nil {
		t.Error("Seal with a short key: expected error")
	}
}

func TestLocalKeyManagerWrapUnwrap(t *testing.T) {
	ctx := t.Context()
	km, err := NewLocalKeyManager(map[string][]byte{"k1": mustKey(t)}, "k1")
	if err != nil {
		t.Fatalf("NewLocalKeyManager: %v", err)
	}
	dek := mustKey(t)
	aad := []byte("dek:doc-1")

	wk, err := km.Wrap(ctx, dek, aad)
	if err != nil {
		t.Fatalf("Wrap: %v", err)
	}
	if wk.KEKID != "k1" || bytes.Contains(wk.Ciphertext, dek) {
		t.Fatalf("unexpected wrapped key: %+v", wk)
	}
	got, err := km.Unwrap(ctx, wk, aad)
	if err != nil || !bytes.Equal(got, dek) {
		t.Fatalf("Unwrap = %x, %v", got, err)
	}
	if _, err := km.Unwrap(ctx, wk, []byte("dek:doc-2")); !errors.Is(err, ErrDecrypt) {
		t.Errorf("unwrap with another document's AAD: err = %v", err)
	}
}

func TestLocalKeyManagerRotation(t *testing.T) {
	ctx := t.Context()
	k1, k2 := mustKey(t), mustKey(t)

	old, _ := NewLocalKeyManager(map[string][]byte{"k1": k1}, "k1")
	dek := mustKey(t)
	wrappedOld, _ := old.Wrap(ctx, dek, nil)

	rotated, err := NewLocalKeyManager(map[string][]byte{"k1": k1, "k2": k2}, "k2")
	if err != nil {
		t.Fatalf("NewLocalKeyManager: %v", err)
	}
	if got, err := rotated.Unwrap(ctx, wrappedOld, nil); err != nil || !bytes.Equal(got, dek) {
		t.Fatalf("old wrapped key must stay readable after rotation: %v", err)
	}
	wrappedNew, _ := rotated.Wrap(ctx, dek, nil)
	if wrappedNew.KEKID != "k2" {
		t.Errorf("new keys must be wrapped with the active KEK, got %q", wrappedNew.KEKID)
	}

	retired, _ := NewLocalKeyManager(map[string][]byte{"k2": k2}, "k2")
	if _, err := retired.Unwrap(ctx, wrappedOld, nil); !errors.Is(err, ErrUnknownKEK) {
		t.Errorf("unwrap with a retired KEK: err = %v, want %v", err, ErrUnknownKEK)
	}
}

func TestNewLocalKeyManagerValidation(t *testing.T) {
	good := mustKey(t)
	tests := map[string]struct {
		keys   map[string][]byte
		active string
	}{
		"no keys":        {nil, "k1"},
		"short key":      {map[string][]byte{"k1": []byte("short")}, "k1"},
		"missing active": {map[string][]byte{"k1": good}, "k2"},
		"bad id":         {map[string][]byte{"k:1": good}, "k:1"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := NewLocalKeyManager(tt.keys, tt.active); err == nil {
				t.Error("expected error")
			}
		})
	}
}

func TestParseMasterKeys(t *testing.T) {
	k1, k2 := mustKey(t), mustKey(t)
	enc := base64.StdEncoding.EncodeToString
	keys, err := ParseMasterKeys("k1:" + enc(k1) + ", k2:" + enc(k2))
	if err != nil {
		t.Fatalf("ParseMasterKeys: %v", err)
	}
	if !bytes.Equal(keys["k1"], k1) || !bytes.Equal(keys["k2"], k2) {
		t.Errorf("parsed keys do not match")
	}

	for _, bad := range []string{"nocolon", ":" + enc(k1), "k1:not-base64!", "k1:" + enc(k1) + ",k1:" + enc(k2)} {
		if _, err := ParseMasterKeys(bad); err == nil {
			t.Errorf("ParseMasterKeys(%q): expected error", bad)
		}
	}
}
