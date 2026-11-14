package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/dNertyco/secretum/internal/documents"
)

// Documents is a PostgreSQL-backed documents.Repository.
type Documents struct {
	pool *pgxpool.Pool
}

// NewDocuments returns a document repository.
func NewDocuments(pool *pgxpool.Pool) *Documents {
	return &Documents{pool: pool}
}

var _ documents.Repository = (*Documents)(nil)

func (r *Documents) inTx(ctx context.Context, fn func(pgx.Tx) error) error {
	return pgx.BeginFunc(ctx, r.pool, fn)
}

// CreateDocument implements documents.Repository.
func (r *Documents) CreateDocument(ctx context.Context, d documents.DocumentRecord, v documents.VersionRecord) error {
	return r.inTx(ctx, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `
			INSERT INTO documents (id, owner_id, name_ciphertext, meta_wrapped_key, meta_kek_id,
			                       current_version, created_at, updated_at)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
			d.ID, d.OwnerID, d.NameCiphertext, d.MetaKey.Ciphertext, d.MetaKey.KEKID,
			d.CurrentVersion, d.CreatedAt, d.UpdatedAt); err != nil {
			return fmt.Errorf("insert document: %w", err)
		}
		if err := insertVersion(ctx, tx, v); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO document_permissions (document_id, user_id, role, granted_by, granted_at)
			VALUES ($1, $2, 'owner', $2, $3)`,
			d.ID, d.OwnerID, d.CreatedAt); err != nil {
			return fmt.Errorf("insert owner permission: %w", err)
		}
		return nil
	})
}

func insertVersion(ctx context.Context, tx pgx.Tx, v documents.VersionRecord) error {
	_, err := tx.Exec(ctx, `
		INSERT INTO document_versions (document_id, version, blob_key, wrapped_key, kek_id,
		                               size, content_type, created_by, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
		v.DocumentID, v.Number, v.BlobKey, v.Key.Ciphertext, v.Key.KEKID,
		v.Size, v.ContentType, v.CreatedBy, v.CreatedAt)
	if err != nil {
		return fmt.Errorf("insert version: %w", err)
	}
	return nil
}

const documentColumns = `
	d.id, d.owner_id, d.name_ciphertext, d.meta_wrapped_key, d.meta_kek_id,
	d.current_version, d.created_at, d.updated_at, v.size, v.content_type`

func scanDocument(row pgx.Row, extra ...any) (documents.DocumentRecord, error) {
	var d documents.DocumentRecord
	dest := append([]any{
		&d.ID, &d.OwnerID, &d.NameCiphertext, &d.MetaKey.Ciphertext, &d.MetaKey.KEKID,
		&d.CurrentVersion, &d.CreatedAt, &d.UpdatedAt, &d.Size, &d.ContentType,
	}, extra...)
	err := row.Scan(dest...)
	return d, err
}

// Document implements documents.Repository.
func (r *Documents) Document(ctx context.Context, id, userID uuid.UUID) (documents.DocumentRecord, documents.Role, error) {
	var role string
	d, err := scanDocument(r.pool.QueryRow(ctx, `
		SELECT `+documentColumns+`, COALESCE(p.role, '')
		FROM documents d
		JOIN document_versions v ON v.document_id = d.id AND v.version = d.current_version
		LEFT JOIN document_permissions p ON p.document_id = d.id AND p.user_id = $2
		WHERE d.id = $1 AND d.deleted_at IS NULL`,
		id, userID), &role)
	if errors.Is(err, pgx.ErrNoRows) {
		return documents.DocumentRecord{}, "", documents.ErrNotFound
	}
	if err != nil {
		return documents.DocumentRecord{}, "", fmt.Errorf("select document: %w", err)
	}
	return d, documents.Role(role), nil
}

// ListDocuments implements documents.Repository. Document IDs are UUIDv7, so
// ordering by ID is ordering by creation time, and the cursor is the last ID.
func (r *Documents) ListDocuments(ctx context.Context, userID, after uuid.UUID, limit int) ([]documents.DocumentWithRole, error) {
	var cursor *uuid.UUID
	if after != uuid.Nil {
		cursor = &after
	}
	rows, err := r.pool.Query(ctx, `
		SELECT `+documentColumns+`, p.role
		FROM document_permissions p
		JOIN documents d ON d.id = p.document_id
		JOIN document_versions v ON v.document_id = d.id AND v.version = d.current_version
		WHERE p.user_id = $1
		  AND d.deleted_at IS NULL
		  AND ($2::uuid IS NULL OR p.document_id < $2)
		ORDER BY p.document_id DESC
		LIMIT $3`,
		userID, cursor, limit)
	if err != nil {
		return nil, fmt.Errorf("list documents: %w", err)
	}
	defer rows.Close()

	var out []documents.DocumentWithRole
	for rows.Next() {
		var role string
		d, err := scanDocument(rows, &role)
		if err != nil {
			return nil, fmt.Errorf("scan document: %w", err)
		}
		out = append(out, documents.DocumentWithRole{DocumentRecord: d, Role: documents.Role(role)})
	}
	return out, rows.Err()
}

// AddVersion implements documents.Repository. The conditional UPDATE is an
// optimistic lock: concurrent uploads of the same version number cannot both
// succeed.
func (r *Documents) AddVersion(ctx context.Context, v documents.VersionRecord) error {
	return r.inTx(ctx, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `
			UPDATE documents SET current_version = $2, updated_at = $3
			WHERE id = $1 AND current_version = $2 - 1 AND deleted_at IS NULL`,
			v.DocumentID, v.Number, v.CreatedAt)
		if err != nil {
			return fmt.Errorf("advance version: %w", err)
		}
		if tag.RowsAffected() == 0 {
			return documents.ErrConflict
		}
		return insertVersion(ctx, tx, v)
	})
}

const versionColumns = `document_id, version, blob_key, wrapped_key, kek_id, size, content_type, created_by, created_at`

func scanVersion(row pgx.Row) (documents.VersionRecord, error) {
	var v documents.VersionRecord
	err := row.Scan(&v.DocumentID, &v.Number, &v.BlobKey, &v.Key.Ciphertext, &v.Key.KEKID,
		&v.Size, &v.ContentType, &v.CreatedBy, &v.CreatedAt)
	return v, err
}

// Version implements documents.Repository.
func (r *Documents) Version(ctx context.Context, documentID uuid.UUID, number int) (documents.VersionRecord, error) {
	v, err := scanVersion(r.pool.QueryRow(ctx, `
		SELECT `+versionColumns+` FROM document_versions
		WHERE document_id = $1 AND version = $2 AND wrapped_key IS NOT NULL`,
		documentID, number))
	if errors.Is(err, pgx.ErrNoRows) {
		return documents.VersionRecord{}, documents.ErrNotFound
	}
	if err != nil {
		return documents.VersionRecord{}, fmt.Errorf("select version: %w", err)
	}
	return v, nil
}

// Versions implements documents.Repository.
func (r *Documents) Versions(ctx context.Context, documentID uuid.UUID) ([]documents.VersionRecord, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT `+versionColumns+` FROM document_versions
		WHERE document_id = $1 AND wrapped_key IS NOT NULL
		ORDER BY version`,
		documentID)
	if err != nil {
		return nil, fmt.Errorf("list versions: %w", err)
	}
	defer rows.Close()

	var out []documents.VersionRecord
	for rows.Next() {
		v, err := scanVersion(rows)
		if err != nil {
			return nil, fmt.Errorf("scan version: %w", err)
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

// Rename implements documents.Repository.
func (r *Documents) Rename(ctx context.Context, documentID uuid.UUID, nameCiphertext []byte, at time.Time) error {
	tag, err := r.pool.Exec(ctx, `
		UPDATE documents SET name_ciphertext = $2, updated_at = $3
		WHERE id = $1 AND deleted_at IS NULL`,
		documentID, nameCiphertext, at)
	if err != nil {
		return fmt.Errorf("rename document: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return documents.ErrNotFound
	}
	return nil
}

// Shred implements documents.Repository.
func (r *Documents) Shred(ctx context.Context, documentID uuid.UUID, at time.Time) ([]string, error) {
	var blobKeys []string
	err := r.inTx(ctx, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `
			UPDATE documents
			SET deleted_at = $2, updated_at = $2, name_ciphertext = NULL, meta_wrapped_key = NULL
			WHERE id = $1 AND deleted_at IS NULL`,
			documentID, at)
		if err != nil {
			return fmt.Errorf("mark document deleted: %w", err)
		}
		if tag.RowsAffected() == 0 {
			return documents.ErrNotFound
		}

		rows, err := tx.Query(ctx, `
			UPDATE document_versions SET wrapped_key = NULL
			WHERE document_id = $1
			RETURNING blob_key`,
			documentID)
		if err != nil {
			return fmt.Errorf("destroy version keys: %w", err)
		}
		blobKeys, err = pgx.CollectRows(rows, pgx.RowTo[string])
		if err != nil {
			return fmt.Errorf("collect blob keys: %w", err)
		}

		if _, err := tx.Exec(ctx, `DELETE FROM document_permissions WHERE document_id = $1`, documentID); err != nil {
			return fmt.Errorf("delete permissions: %w", err)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return blobKeys, nil
}

// SetPermission implements documents.Repository. The owner's row is never
// modified.
func (r *Documents) SetPermission(ctx context.Context, documentID, userID uuid.UUID, role documents.Role, grantedBy uuid.UUID, at time.Time) error {
	_, err := r.pool.Exec(ctx, `
		INSERT INTO document_permissions (document_id, user_id, role, granted_by, granted_at)
		VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (document_id, user_id) DO UPDATE
		SET role = EXCLUDED.role, granted_by = EXCLUDED.granted_by, granted_at = EXCLUDED.granted_at
		WHERE document_permissions.role <> 'owner'`,
		documentID, userID, string(role), grantedBy, at)
	if err != nil {
		return fmt.Errorf("set permission: %w", err)
	}
	return nil
}

// RemovePermission implements documents.Repository.
func (r *Documents) RemovePermission(ctx context.Context, documentID, userID uuid.UUID) error {
	tag, err := r.pool.Exec(ctx, `
		DELETE FROM document_permissions
		WHERE document_id = $1 AND user_id = $2 AND role <> 'owner'`,
		documentID, userID)
	if err != nil {
		return fmt.Errorf("remove permission: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return documents.ErrNotFound
	}
	return nil
}

// Permissions implements documents.Repository.
func (r *Documents) Permissions(ctx context.Context, documentID uuid.UUID) ([]documents.Permission, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT p.user_id, u.username, p.role, p.granted_at
		FROM document_permissions p
		JOIN users u ON u.id = p.user_id
		WHERE p.document_id = $1
		ORDER BY p.granted_at, u.username`,
		documentID)
	if err != nil {
		return nil, fmt.Errorf("list permissions: %w", err)
	}
	defer rows.Close()

	var out []documents.Permission
	for rows.Next() {
		var p documents.Permission
		var role string
		if err := rows.Scan(&p.UserID, &p.Username, &role, &p.GrantedAt); err != nil {
			return nil, fmt.Errorf("scan permission: %w", err)
		}
		p.Role = documents.Role(role)
		out = append(out, p)
	}
	return out, rows.Err()
}

// RecordAudit implements documents.Repository.
func (r *Documents) RecordAudit(ctx context.Context, e documents.AuditEvent) error {
	_, err := r.pool.Exec(ctx, `
		INSERT INTO audit_events (occurred_at, actor_id, action, document_id, outcome, request_id, client_ip)
		VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		e.OccurredAt, nullUUID(e.ActorID), e.Action, nullUUID(e.DocumentID), e.Outcome, e.RequestID, e.ClientIP)
	if err != nil {
		return fmt.Errorf("insert audit event: %w", err)
	}
	return nil
}

// AuditEvents implements documents.Repository.
func (r *Documents) AuditEvents(ctx context.Context, documentID uuid.UUID, limit int) ([]documents.AuditEvent, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT id, occurred_at, actor_id, action, document_id, outcome, request_id, client_ip
		FROM audit_events
		WHERE document_id = $1
		ORDER BY id DESC
		LIMIT $2`,
		documentID, limit)
	if err != nil {
		return nil, fmt.Errorf("list audit events: %w", err)
	}
	defer rows.Close()

	var out []documents.AuditEvent
	for rows.Next() {
		var e documents.AuditEvent
		var actor, doc uuid.NullUUID
		if err := rows.Scan(&e.ID, &e.OccurredAt, &actor, &e.Action, &doc, &e.Outcome, &e.RequestID, &e.ClientIP); err != nil {
			return nil, fmt.Errorf("scan audit event: %w", err)
		}
		e.ActorID, e.DocumentID = actor.UUID, doc.UUID
		out = append(out, e)
	}
	return out, rows.Err()
}

func nullUUID(id uuid.UUID) uuid.NullUUID {
	return uuid.NullUUID{UUID: id, Valid: id != uuid.Nil}
}
