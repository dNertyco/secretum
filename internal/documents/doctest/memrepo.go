// Package doctest provides an in-memory documents.Repository for fast unit
// tests. The PostgreSQL implementation is covered by integration tests that
// exercise the same contract.
package doctest

import (
	"bytes"
	"cmp"
	"context"
	"slices"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/dNertyco/secretum/internal/auth"
	"github.com/dNertyco/secretum/internal/documents"
)

type docState struct {
	rec      documents.DocumentRecord
	deleted  bool
	versions map[int]documents.VersionRecord
	perms    map[uuid.UUID]documents.Permission
}

// MemRepo is an in-memory documents.Repository.
type MemRepo struct {
	mu    sync.Mutex
	users auth.UserRepository
	docs  map[uuid.UUID]*docState
	audit []documents.AuditEvent
}

var _ documents.Repository = (*MemRepo)(nil)

// NewMemRepo returns an empty repository; users resolves usernames for
// permission listings.
func NewMemRepo(users auth.UserRepository) *MemRepo {
	return &MemRepo{users: users, docs: make(map[uuid.UUID]*docState)}
}

func (m *MemRepo) withCurrent(st *docState) documents.DocumentRecord {
	rec := st.rec
	rec.NameCiphertext = bytes.Clone(rec.NameCiphertext)
	cur := st.versions[rec.CurrentVersion]
	rec.Size, rec.ContentType = cur.Size, cur.ContentType
	return rec
}

// CreateDocument implements documents.Repository.
func (m *MemRepo) CreateDocument(_ context.Context, d documents.DocumentRecord, v documents.VersionRecord) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.docs[d.ID] = &docState{
		rec:      d,
		versions: map[int]documents.VersionRecord{v.Number: v},
		perms: map[uuid.UUID]documents.Permission{
			d.OwnerID: {UserID: d.OwnerID, Role: documents.RoleOwner, GrantedAt: d.CreatedAt},
		},
	}
	return nil
}

// Document implements documents.Repository.
func (m *MemRepo) Document(_ context.Context, id, userID uuid.UUID) (documents.DocumentRecord, documents.Role, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	st, ok := m.docs[id]
	if !ok || st.deleted {
		return documents.DocumentRecord{}, "", documents.ErrNotFound
	}
	return m.withCurrent(st), st.perms[userID].Role, nil
}

// ListDocuments implements documents.Repository.
func (m *MemRepo) ListDocuments(_ context.Context, userID, after uuid.UUID, limit int) ([]documents.DocumentWithRole, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []documents.DocumentWithRole
	for id, st := range m.docs {
		p, ok := st.perms[userID]
		if st.deleted || !ok || (after != uuid.Nil && bytes.Compare(id[:], after[:]) >= 0) {
			continue
		}
		out = append(out, documents.DocumentWithRole{DocumentRecord: m.withCurrent(st), Role: p.Role})
	}
	slices.SortFunc(out, func(a, b documents.DocumentWithRole) int { return bytes.Compare(b.ID[:], a.ID[:]) })
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

// AddVersion implements documents.Repository.
func (m *MemRepo) AddVersion(_ context.Context, v documents.VersionRecord) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	st, ok := m.docs[v.DocumentID]
	if !ok || st.deleted || st.rec.CurrentVersion != v.Number-1 {
		return documents.ErrConflict
	}
	st.versions[v.Number] = v
	st.rec.CurrentVersion = v.Number
	st.rec.UpdatedAt = v.CreatedAt
	return nil
}

// Version implements documents.Repository.
func (m *MemRepo) Version(_ context.Context, documentID uuid.UUID, number int) (documents.VersionRecord, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	st, ok := m.docs[documentID]
	if !ok {
		return documents.VersionRecord{}, documents.ErrNotFound
	}
	v, ok := st.versions[number]
	if !ok || v.Key.Ciphertext == nil {
		return documents.VersionRecord{}, documents.ErrNotFound
	}
	return v, nil
}

// Versions implements documents.Repository.
func (m *MemRepo) Versions(_ context.Context, documentID uuid.UUID) ([]documents.VersionRecord, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	st, ok := m.docs[documentID]
	if !ok {
		return nil, nil
	}
	out := make([]documents.VersionRecord, 0, len(st.versions))
	for _, v := range st.versions {
		out = append(out, v)
	}
	slices.SortFunc(out, func(a, b documents.VersionRecord) int { return cmp.Compare(a.Number, b.Number) })
	return out, nil
}

// Rename implements documents.Repository.
func (m *MemRepo) Rename(_ context.Context, documentID uuid.UUID, nameCiphertext []byte, at time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	st, ok := m.docs[documentID]
	if !ok || st.deleted {
		return documents.ErrNotFound
	}
	st.rec.NameCiphertext = bytes.Clone(nameCiphertext)
	st.rec.UpdatedAt = at
	return nil
}

// Shred implements documents.Repository.
func (m *MemRepo) Shred(_ context.Context, documentID uuid.UUID, at time.Time) ([]string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	st, ok := m.docs[documentID]
	if !ok || st.deleted {
		return nil, documents.ErrNotFound
	}
	st.deleted = true
	st.rec.NameCiphertext = nil
	st.rec.MetaKey.Ciphertext = nil
	st.rec.UpdatedAt = at
	keys := make([]string, 0, len(st.versions))
	for n, v := range st.versions {
		keys = append(keys, v.BlobKey)
		v.Key.Ciphertext = nil
		st.versions[n] = v
	}
	st.perms = map[uuid.UUID]documents.Permission{}
	return keys, nil
}

// SetPermission implements documents.Repository.
func (m *MemRepo) SetPermission(_ context.Context, documentID, userID uuid.UUID, role documents.Role, _ uuid.UUID, at time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	st, ok := m.docs[documentID]
	if !ok || st.deleted {
		return documents.ErrNotFound
	}
	if st.perms[userID].Role == documents.RoleOwner {
		return nil
	}
	st.perms[userID] = documents.Permission{UserID: userID, Role: role, GrantedAt: at}
	return nil
}

// RemovePermission implements documents.Repository.
func (m *MemRepo) RemovePermission(_ context.Context, documentID, userID uuid.UUID) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	st, ok := m.docs[documentID]
	if !ok {
		return documents.ErrNotFound
	}
	p, ok := st.perms[userID]
	if !ok || p.Role == documents.RoleOwner {
		return documents.ErrNotFound
	}
	delete(st.perms, userID)
	return nil
}

// Permissions implements documents.Repository.
func (m *MemRepo) Permissions(ctx context.Context, documentID uuid.UUID) ([]documents.Permission, error) {
	m.mu.Lock()
	st, ok := m.docs[documentID]
	var perms []documents.Permission
	if ok {
		for _, p := range st.perms {
			perms = append(perms, p)
		}
	}
	m.mu.Unlock()

	for i, p := range perms {
		u, err := m.users.UserByID(ctx, p.UserID)
		if err != nil {
			return nil, err
		}
		perms[i].Username = u.Username
	}
	slices.SortFunc(perms, func(a, b documents.Permission) int { return a.GrantedAt.Compare(b.GrantedAt) })
	return perms, nil
}

// RecordAudit implements documents.Repository.
func (m *MemRepo) RecordAudit(_ context.Context, e documents.AuditEvent) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	e.ID = int64(len(m.audit) + 1)
	m.audit = append(m.audit, e)
	return nil
}

// AuditEvents implements documents.Repository.
func (m *MemRepo) AuditEvents(_ context.Context, documentID uuid.UUID, limit int) ([]documents.AuditEvent, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []documents.AuditEvent
	for i := len(m.audit) - 1; i >= 0 && len(out) < limit; i-- {
		if m.audit[i].DocumentID == documentID {
			out = append(out, m.audit[i])
		}
	}
	return out, nil
}

// MetaKey returns the stored wrapped metadata key of a document. It is
// intended for tests that verify crypto-shredding.
func (m *MemRepo) MetaKey(id uuid.UUID) []byte {
	m.mu.Lock()
	defer m.mu.Unlock()
	if st, ok := m.docs[id]; ok {
		return st.rec.MetaKey.Ciphertext
	}
	return nil
}
