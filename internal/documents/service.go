package documents

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/google/uuid"

	"github.com/dNertyco/secretum/internal/auth"
	"github.com/dNertyco/secretum/internal/blob"
	"github.com/dNertyco/secretum/internal/envelope"
)

const (
	maxNameLen      = 255
	maxListLimit    = 100
	auditEventLimit = 100
)

// Service implements document operations with authorization, encryption and
// audit.
type Service struct {
	repo   Repository
	blobs  blob.Store
	keys   envelope.KeyManager
	users  UserLookup
	logger *slog.Logger
	now    func() time.Time
}

// NewService returns a document service.
func NewService(repo Repository, blobs blob.Store, keys envelope.KeyManager, users UserLookup, logger *slog.Logger) *Service {
	return &Service{repo: repo, blobs: blobs, keys: keys, users: users, logger: logger, now: time.Now}
}

// Additional authenticated data binds every ciphertext and wrapped key to
// the document (and version) it belongs to.
func nameAAD(doc uuid.UUID) []byte { return []byte("secretum/v1/name/" + doc.String()) }

func contentAAD(doc uuid.UUID, version int) []byte {
	return fmt.Appendf(nil, "secretum/v1/content/%s/%d", doc, version)
}

// dekAAD is used to wrap data keys; version 0 is the metadata key.
func dekAAD(doc uuid.UUID, version int) []byte {
	return fmt.Appendf(nil, "secretum/v1/dek/%s/%d", doc, version)
}

func validateName(name string) (string, error) {
	name = strings.TrimSpace(name)
	if name == "" || utf8.RuneCountInString(name) > maxNameLen {
		return "", fmt.Errorf("%w: name must be 1-%d characters", ErrInvalidArgument, maxNameLen)
	}
	if strings.IndexFunc(name, unicode.IsControl) >= 0 || !utf8.ValidString(name) {
		return "", fmt.Errorf("%w: name contains invalid characters", ErrInvalidArgument)
	}
	return name, nil
}

// Upload stores a new encrypted document owned by the actor.
func (s *Service) Upload(ctx context.Context, actor Actor, name string, data []byte) (Document, error) {
	name, err := validateName(name)
	if err != nil {
		return Document{}, err
	}
	if len(data) == 0 {
		return Document{}, fmt.Errorf("%w: file is empty", ErrInvalidArgument)
	}

	id, err := uuid.NewV7()
	if err != nil {
		return Document{}, fmt.Errorf("generate document id: %w", err)
	}
	now := s.now().UTC()

	nameCT, metaKey, err := s.encryptName(ctx, id, name)
	if err != nil {
		return Document{}, err
	}
	v, err := s.storeVersion(ctx, actor, id, 1, data, now)
	if err != nil {
		return Document{}, err
	}

	rec := DocumentRecord{
		ID: id, OwnerID: actor.UserID, NameCiphertext: nameCT, MetaKey: metaKey,
		CurrentVersion: 1, CreatedAt: now, UpdatedAt: now,
		Size: v.Size, ContentType: v.ContentType,
	}
	if err := s.repo.CreateDocument(ctx, rec, v); err != nil {
		s.deleteBlobs(ctx, v.BlobKey)
		return Document{}, fmt.Errorf("create document: %w", err)
	}
	s.audit(ctx, actor, ActionCreate, id, OutcomeSuccess)
	return toDocument(rec, name, RoleOwner), nil
}

// AddVersion stores new content for a document. Requires editor access.
func (s *Service) AddVersion(ctx context.Context, actor Actor, id uuid.UUID, data []byte) (Version, error) {
	if len(data) == 0 {
		return Version{}, fmt.Errorf("%w: file is empty", ErrInvalidArgument)
	}
	rec, _, err := s.authorize(ctx, actor, id, RoleEditor, ActionVersion)
	if err != nil {
		return Version{}, err
	}

	v, err := s.storeVersion(ctx, actor, id, rec.CurrentVersion+1, data, s.now().UTC())
	if err != nil {
		return Version{}, err
	}
	if err := s.repo.AddVersion(ctx, v); err != nil {
		s.deleteBlobs(ctx, v.BlobKey)
		if errors.Is(err, ErrConflict) {
			return Version{}, ErrConflict
		}
		return Version{}, fmt.Errorf("add version: %w", err)
	}
	s.audit(ctx, actor, ActionVersion, id, OutcomeSuccess)
	return toVersion(v), nil
}

// Get returns a document's metadata. Requires viewer access.
func (s *Service) Get(ctx context.Context, actor Actor, id uuid.UUID) (Document, error) {
	rec, role, err := s.authorize(ctx, actor, id, RoleViewer, "")
	if err != nil {
		return Document{}, err
	}
	name, err := s.decryptName(ctx, rec)
	if err != nil {
		return Document{}, err
	}
	return toDocument(rec, name, role), nil
}

// List returns documents the actor can access, newest first. The second
// result is the cursor for the next page, or uuid.Nil on the last page.
func (s *Service) List(ctx context.Context, actor Actor, after uuid.UUID, limit int) ([]Document, uuid.UUID, error) {
	if limit <= 0 || limit > maxListLimit {
		return nil, uuid.Nil, fmt.Errorf("%w: limit must be 1-%d", ErrInvalidArgument, maxListLimit)
	}
	recs, err := s.repo.ListDocuments(ctx, actor.UserID, after, limit+1)
	if err != nil {
		return nil, uuid.Nil, fmt.Errorf("list documents: %w", err)
	}
	next := uuid.Nil
	if len(recs) > limit {
		recs = recs[:limit]
		next = recs[limit-1].ID
	}
	docs := make([]Document, 0, len(recs))
	for _, r := range recs {
		name, err := s.decryptName(ctx, r.DocumentRecord)
		if err != nil {
			return nil, uuid.Nil, err
		}
		docs = append(docs, toDocument(r.DocumentRecord, name, r.Role))
	}
	return docs, next, nil
}

// Versions lists a document's versions. Requires viewer access.
func (s *Service) Versions(ctx context.Context, actor Actor, id uuid.UUID) ([]Version, error) {
	if _, _, err := s.authorize(ctx, actor, id, RoleViewer, ""); err != nil {
		return nil, err
	}
	recs, err := s.repo.Versions(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("list versions: %w", err)
	}
	out := make([]Version, 0, len(recs))
	for _, r := range recs {
		out = append(out, toVersion(r))
	}
	return out, nil
}

// Download decrypts a document version (0 means current). Requires viewer
// access. The download is audited before any content is returned; if the
// audit record cannot be written, the download fails.
func (s *Service) Download(ctx context.Context, actor Actor, id uuid.UUID, version int) (Content, error) {
	rec, role, err := s.authorize(ctx, actor, id, RoleViewer, ActionDownload)
	if err != nil {
		return Content{}, err
	}
	if version == 0 {
		version = rec.CurrentVersion
	}
	v, err := s.repo.Version(ctx, id, version)
	if err != nil {
		return Content{}, err
	}

	ciphertext, err := s.blobs.Get(ctx, v.BlobKey)
	if err != nil {
		return Content{}, fmt.Errorf("get blob: %w", err)
	}
	dek, err := s.keys.Unwrap(ctx, v.Key, dekAAD(id, v.Number))
	if err != nil {
		return Content{}, fmt.Errorf("unwrap data key: %w", err)
	}
	defer clear(dek)
	data, err := envelope.Open(dek, ciphertext, contentAAD(id, v.Number))
	if err != nil {
		return Content{}, fmt.Errorf("decrypt content: %w", err)
	}

	name, err := s.decryptName(ctx, rec)
	if err != nil {
		return Content{}, err
	}
	if err := s.recordAudit(ctx, actor, ActionDownload, id, OutcomeSuccess); err != nil {
		return Content{}, err
	}
	return Content{Document: toDocument(rec, name, role), Version: toVersion(v), Data: data}, nil
}

// Rename changes a document's name. Requires editor access.
func (s *Service) Rename(ctx context.Context, actor Actor, id uuid.UUID, name string) (Document, error) {
	name, err := validateName(name)
	if err != nil {
		return Document{}, err
	}
	rec, role, err := s.authorize(ctx, actor, id, RoleEditor, ActionRename)
	if err != nil {
		return Document{}, err
	}
	metaKey, err := s.keys.Unwrap(ctx, rec.MetaKey, dekAAD(id, 0))
	if err != nil {
		return Document{}, fmt.Errorf("unwrap metadata key: %w", err)
	}
	defer clear(metaKey)
	nameCT, err := envelope.Seal(metaKey, []byte(name), nameAAD(id))
	if err != nil {
		return Document{}, err
	}
	now := s.now().UTC()
	if err := s.repo.Rename(ctx, id, nameCT, now); err != nil {
		return Document{}, fmt.Errorf("rename: %w", err)
	}
	s.audit(ctx, actor, ActionRename, id, OutcomeSuccess)
	rec.UpdatedAt = now
	return toDocument(rec, name, role), nil
}

// Delete crypto-shreds a document: all its wrapped keys are destroyed, so
// its content becomes unreadable everywhere, including backups. Ciphertext
// blobs are then removed on a best-effort basis. Requires owner access.
func (s *Service) Delete(ctx context.Context, actor Actor, id uuid.UUID) error {
	if _, _, err := s.authorize(ctx, actor, id, RoleOwner, ActionDelete); err != nil {
		return err
	}
	blobKeys, err := s.repo.Shred(ctx, id, s.now().UTC())
	if err != nil {
		return fmt.Errorf("shred document: %w", err)
	}
	s.audit(ctx, actor, ActionDelete, id, OutcomeSuccess)
	s.deleteBlobs(ctx, blobKeys...)
	return nil
}

// Share grants another user access to a document. Requires owner access.
func (s *Service) Share(ctx context.Context, actor Actor, id uuid.UUID, username string, role Role) error {
	if _, _, err := s.authorize(ctx, actor, id, RoleOwner, ActionShare); err != nil {
		return err
	}
	target, err := s.users.UserByUsername(ctx, auth.NormalizeUsername(username))
	if err != nil {
		return err
	}
	if target.ID == actor.UserID {
		return fmt.Errorf("%w: cannot change the owner's access", ErrInvalidArgument)
	}
	if err := s.repo.SetPermission(ctx, id, target.ID, role, actor.UserID, s.now().UTC()); err != nil {
		return fmt.Errorf("set permission: %w", err)
	}
	s.audit(ctx, actor, ActionShare, id, OutcomeSuccess)
	return nil
}

// Unshare revokes a user's access to a document. Requires owner access.
func (s *Service) Unshare(ctx context.Context, actor Actor, id uuid.UUID, username string) error {
	if _, _, err := s.authorize(ctx, actor, id, RoleOwner, ActionUnshare); err != nil {
		return err
	}
	target, err := s.users.UserByUsername(ctx, auth.NormalizeUsername(username))
	if err != nil {
		return err
	}
	if target.ID == actor.UserID {
		return fmt.Errorf("%w: cannot change the owner's access", ErrInvalidArgument)
	}
	if err := s.repo.RemovePermission(ctx, id, target.ID); err != nil {
		return err
	}
	s.audit(ctx, actor, ActionUnshare, id, OutcomeSuccess)
	return nil
}

// Permissions lists who can access a document. Requires owner access.
func (s *Service) Permissions(ctx context.Context, actor Actor, id uuid.UUID) ([]Permission, error) {
	if _, _, err := s.authorize(ctx, actor, id, RoleOwner, ""); err != nil {
		return nil, err
	}
	return s.repo.Permissions(ctx, id)
}

// AuditLog returns the latest audit events of a document. Requires owner
// access.
func (s *Service) AuditLog(ctx context.Context, actor Actor, id uuid.UUID) ([]AuditEvent, error) {
	if _, _, err := s.authorize(ctx, actor, id, RoleOwner, ""); err != nil {
		return nil, err
	}
	return s.repo.AuditEvents(ctx, id, auditEventLimit)
}

// authorize loads a document and checks that the actor has at least the
// needed role. Users without any access get ErrNotFound, so that document
// existence is not revealed; users with insufficient access get
// ErrForbidden. Denials of audited actions are recorded.
func (s *Service) authorize(ctx context.Context, actor Actor, id uuid.UUID, need Role, action string) (DocumentRecord, Role, error) {
	rec, role, err := s.repo.Document(ctx, id, actor.UserID)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return DocumentRecord{}, "", ErrNotFound
		}
		return DocumentRecord{}, "", fmt.Errorf("load document: %w", err)
	}
	if role.AtLeast(need) {
		return rec, role, nil
	}
	if action != "" {
		s.audit(ctx, actor, action, id, OutcomeDenied)
	}
	if role.AtLeast(RoleViewer) {
		return DocumentRecord{}, "", ErrForbidden
	}
	return DocumentRecord{}, "", ErrNotFound
}

func (s *Service) storeVersion(ctx context.Context, actor Actor, doc uuid.UUID, number int, data []byte, at time.Time) (VersionRecord, error) {
	dek, err := envelope.NewDataKey()
	if err != nil {
		return VersionRecord{}, err
	}
	defer clear(dek)

	wrapped, err := s.keys.Wrap(ctx, dek, dekAAD(doc, number))
	if err != nil {
		return VersionRecord{}, err
	}
	ciphertext, err := envelope.Seal(dek, data, contentAAD(doc, number))
	if err != nil {
		return VersionRecord{}, err
	}
	// A random suffix keeps concurrent uploads of the same version number
	// from overwriting each other before the conflict is detected.
	key := fmt.Sprintf("documents/%s/%d-%s", doc, number, uuid.NewString())
	if err := s.blobs.Put(ctx, key, ciphertext); err != nil {
		return VersionRecord{}, fmt.Errorf("put blob: %w", err)
	}
	return VersionRecord{
		DocumentID:  doc,
		Number:      number,
		BlobKey:     key,
		Key:         wrapped,
		Size:        int64(len(data)),
		ContentType: http.DetectContentType(data),
		CreatedBy:   actor.UserID,
		CreatedAt:   at,
	}, nil
}

func (s *Service) encryptName(ctx context.Context, doc uuid.UUID, name string) ([]byte, envelope.WrappedKey, error) {
	metaKey, err := envelope.NewDataKey()
	if err != nil {
		return nil, envelope.WrappedKey{}, err
	}
	defer clear(metaKey)
	wrapped, err := s.keys.Wrap(ctx, metaKey, dekAAD(doc, 0))
	if err != nil {
		return nil, envelope.WrappedKey{}, err
	}
	ct, err := envelope.Seal(metaKey, []byte(name), nameAAD(doc))
	if err != nil {
		return nil, envelope.WrappedKey{}, err
	}
	return ct, wrapped, nil
}

func (s *Service) decryptName(ctx context.Context, rec DocumentRecord) (string, error) {
	metaKey, err := s.keys.Unwrap(ctx, rec.MetaKey, dekAAD(rec.ID, 0))
	if err != nil {
		return "", fmt.Errorf("unwrap metadata key: %w", err)
	}
	defer clear(metaKey)
	name, err := envelope.Open(metaKey, rec.NameCiphertext, nameAAD(rec.ID))
	if err != nil {
		return "", fmt.Errorf("decrypt name: %w", err)
	}
	return string(name), nil
}

func (s *Service) recordAudit(ctx context.Context, actor Actor, action string, doc uuid.UUID, outcome string) error {
	err := s.repo.RecordAudit(ctx, AuditEvent{
		OccurredAt: s.now().UTC(),
		ActorID:    actor.UserID,
		Action:     action,
		DocumentID: doc,
		Outcome:    outcome,
		RequestID:  actor.RequestID,
		ClientIP:   actor.ClientIP,
	})
	if err != nil {
		return fmt.Errorf("record audit event: %w", err)
	}
	return nil
}

// audit records an event after an operation has completed. A failure is
// logged rather than returned, because the operation itself has succeeded.
func (s *Service) audit(ctx context.Context, actor Actor, action string, doc uuid.UUID, outcome string) {
	if err := s.recordAudit(ctx, actor, action, doc, outcome); err != nil {
		s.logger.ErrorContext(ctx, "audit event lost", "err", err, "action", action, "document_id", doc, "outcome", outcome)
	}
}

func (s *Service) deleteBlobs(ctx context.Context, keys ...string) {
	for _, k := range keys {
		if err := s.blobs.Delete(ctx, k); err != nil {
			s.logger.WarnContext(ctx, "orphaned blob", "err", err, "blob_key", k)
		}
	}
}

func toDocument(rec DocumentRecord, name string, role Role) Document {
	return Document{
		ID:             rec.ID,
		OwnerID:        rec.OwnerID,
		Name:           name,
		Role:           role,
		CurrentVersion: rec.CurrentVersion,
		Size:           rec.Size,
		ContentType:    rec.ContentType,
		CreatedAt:      rec.CreatedAt,
		UpdatedAt:      rec.UpdatedAt,
	}
}

func toVersion(v VersionRecord) Version {
	return Version{Number: v.Number, Size: v.Size, ContentType: v.ContentType, CreatedBy: v.CreatedBy, CreatedAt: v.CreatedAt}
}
