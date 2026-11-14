// Package documents implements encrypted document storage: upload, versions,
// download, sharing, audit and crypto-shredding.
package documents

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/dNertyco/secretum/internal/auth"
	"github.com/dNertyco/secretum/internal/envelope"
)

// Errors returned by Service. ErrInvalidArgument is wrapped with details.
var (
	ErrNotFound        = errors.New("document not found")
	ErrForbidden       = errors.New("insufficient permissions")
	ErrConflict        = errors.New("document was modified concurrently")
	ErrInvalidArgument = errors.New("invalid argument")
)

// Role is a user's level of access to a document.
type Role string

// Roles in ascending order of privilege.
const (
	RoleViewer Role = "viewer"
	RoleEditor Role = "editor"
	RoleOwner  Role = "owner"
)

func (r Role) rank() int {
	switch r {
	case RoleViewer:
		return 1
	case RoleEditor:
		return 2
	case RoleOwner:
		return 3
	default:
		return 0
	}
}

// AtLeast reports whether r grants everything other grants.
func (r Role) AtLeast(other Role) bool { return r.rank() >= other.rank() && r.rank() > 0 }

// ParseShareRole parses a role that can be granted to another user.
// Ownership cannot be granted.
func ParseShareRole(s string) (Role, error) {
	switch r := Role(s); r {
	case RoleViewer, RoleEditor:
		return r, nil
	default:
		return "", fmt.Errorf("%w: role must be %q or %q", ErrInvalidArgument, RoleViewer, RoleEditor)
	}
}

// Actor identifies who performs an operation, for authorization and audit.
type Actor struct {
	UserID    uuid.UUID
	RequestID string
	ClientIP  string
}

// Document is a decrypted view of a document's metadata.
type Document struct {
	ID             uuid.UUID
	OwnerID        uuid.UUID
	Name           string
	Role           Role
	CurrentVersion int
	Size           int64
	ContentType    string
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

// Version describes one stored version of a document's content.
type Version struct {
	Number      int
	Size        int64
	ContentType string
	CreatedBy   uuid.UUID
	CreatedAt   time.Time
}

// Content is a decrypted document version.
type Content struct {
	Document Document
	Version  Version
	Data     []byte
}

// Permission is a user's access to a document.
type Permission struct {
	UserID    uuid.UUID
	Username  string
	Role      Role
	GrantedAt time.Time
}

// Audit actions.
const (
	ActionCreate   = "document.create"
	ActionVersion  = "document.version.create"
	ActionDownload = "document.download"
	ActionRename   = "document.rename"
	ActionDelete   = "document.delete"
	ActionShare    = "document.share"
	ActionUnshare  = "document.unshare"
)

// Audit outcomes.
const (
	OutcomeSuccess = "success"
	OutcomeDenied  = "denied"
)

// AuditEvent is a record of an access attempt.
type AuditEvent struct {
	ID         int64
	OccurredAt time.Time
	ActorID    uuid.UUID
	Action     string
	DocumentID uuid.UUID
	Outcome    string
	RequestID  string
	ClientIP   string
}

// DocumentRecord is a document as persisted: the name is encrypted with a
// per-document metadata key, which is wrapped by the key manager.
type DocumentRecord struct {
	ID             uuid.UUID
	OwnerID        uuid.UUID
	NameCiphertext []byte
	MetaKey        envelope.WrappedKey
	CurrentVersion int
	CreatedAt      time.Time
	UpdatedAt      time.Time

	// Filled by read queries from the current version.
	Size        int64
	ContentType string
}

// VersionRecord is a document version as persisted. Each version has its
// own data key; its content lives in the blob store under BlobKey.
type VersionRecord struct {
	DocumentID  uuid.UUID
	Number      int
	BlobKey     string
	Key         envelope.WrappedKey
	Size        int64
	ContentType string
	CreatedBy   uuid.UUID
	CreatedAt   time.Time
}

// DocumentWithRole is a document record together with the caller's role.
type DocumentWithRole struct {
	DocumentRecord
	Role Role
}

// Repository persists documents, versions, permissions and audit events.
type Repository interface {
	// CreateDocument stores a document, its first version and the owner's
	// permission atomically.
	CreateDocument(ctx context.Context, d DocumentRecord, v VersionRecord) error
	// Document returns a live document and userID's role in it (empty if the
	// user has no access). It returns ErrNotFound for missing or deleted
	// documents.
	Document(ctx context.Context, id, userID uuid.UUID) (DocumentRecord, Role, error)
	// ListDocuments returns live documents userID can access, newest first,
	// with IDs lower than after (uuid.Nil for the first page).
	ListDocuments(ctx context.Context, userID, after uuid.UUID, limit int) ([]DocumentWithRole, error)
	// AddVersion stores v and makes it current. It returns ErrConflict if the
	// current version is not v.Number-1.
	AddVersion(ctx context.Context, v VersionRecord) error
	// Version returns ErrNotFound if the version does not exist or was shredded.
	Version(ctx context.Context, documentID uuid.UUID, number int) (VersionRecord, error)
	Versions(ctx context.Context, documentID uuid.UUID) ([]VersionRecord, error)
	Rename(ctx context.Context, documentID uuid.UUID, nameCiphertext []byte, at time.Time) error
	// Shred marks the document deleted, destroys all its wrapped keys and
	// permissions, and returns the blob keys of its versions.
	Shred(ctx context.Context, documentID uuid.UUID, at time.Time) ([]string, error)
	SetPermission(ctx context.Context, documentID, userID uuid.UUID, role Role, grantedBy uuid.UUID, at time.Time) error
	// RemovePermission returns ErrNotFound if the user has no non-owner access.
	RemovePermission(ctx context.Context, documentID, userID uuid.UUID) error
	Permissions(ctx context.Context, documentID uuid.UUID) ([]Permission, error)
	RecordAudit(ctx context.Context, e AuditEvent) error
	AuditEvents(ctx context.Context, documentID uuid.UUID, limit int) ([]AuditEvent, error)
}

// UserLookup resolves usernames for sharing.
type UserLookup interface {
	UserByUsername(ctx context.Context, username string) (auth.User, error)
}
