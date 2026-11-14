package documents_test

import (
	"bytes"
	"errors"
	"io"
	"log/slog"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/dNertyco/secretum/internal/auth"
	"github.com/dNertyco/secretum/internal/auth/authtest"
	"github.com/dNertyco/secretum/internal/blob"
	"github.com/dNertyco/secretum/internal/documents"
	"github.com/dNertyco/secretum/internal/documents/doctest"
	"github.com/dNertyco/secretum/internal/envelope"
)

type fixture struct {
	t     *testing.T
	svc   *documents.Service
	repo  *doctest.MemRepo
	blobs *blob.Memory
	users *authtest.MemUsers
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	kek, _ := envelope.NewDataKey()
	keys, err := envelope.NewLocalKeyManager(map[string][]byte{"k1": kek}, "k1")
	if err != nil {
		t.Fatalf("NewLocalKeyManager: %v", err)
	}
	users := authtest.NewMemUsers()
	repo := doctest.NewMemRepo(users)
	blobs := blob.NewMemory()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	return &fixture{t: t, svc: documents.NewService(repo, blobs, keys, users, logger), repo: repo, blobs: blobs, users: users}
}

func (f *fixture) user(name string) documents.Actor {
	f.t.Helper()
	u := auth.User{ID: uuid.Must(uuid.NewV7()), Username: name, CreatedAt: time.Now()}
	if err := f.users.CreateUser(f.t.Context(), u); err != nil {
		f.t.Fatalf("CreateUser: %v", err)
	}
	return documents.Actor{UserID: u.ID, RequestID: "req-" + name, ClientIP: "203.0.113.1"}
}

func (f *fixture) upload(actor documents.Actor, name, content string) documents.Document {
	f.t.Helper()
	doc, err := f.svc.Upload(f.t.Context(), actor, name, []byte(content))
	if err != nil {
		f.t.Fatalf("Upload: %v", err)
	}
	return doc
}

func TestUploadDownloadRoundTrip(t *testing.T) {
	f := newFixture(t)
	alice := f.user("alice")
	content := "Service report No. 123: ventilator sensor replaced"

	doc := f.upload(alice, "Report 123", content)
	if doc.Name != "Report 123" || doc.Role != documents.RoleOwner || doc.CurrentVersion != 1 {
		t.Fatalf("unexpected document: %+v", doc)
	}
	if doc.Size != int64(len(content)) || !strings.HasPrefix(doc.ContentType, "text/plain") {
		t.Errorf("size/content type = %d/%q", doc.Size, doc.ContentType)
	}

	got, err := f.svc.Download(t.Context(), alice, doc.ID, 0)
	if err != nil {
		t.Fatalf("Download: %v", err)
	}
	if string(got.Data) != content || got.Version.Number != 1 || got.Document.Name != "Report 123" {
		t.Errorf("Download = %+v", got)
	}
}

func TestStorageHoldsOnlyCiphertext(t *testing.T) {
	f := newFixture(t)
	alice := f.user("alice")
	content := "patient John Doe, ward 7"
	doc := f.upload(alice, "Confidential act", content)

	keys := f.blobs.Keys()
	if len(keys) != 1 {
		t.Fatalf("blob count = %d, want 1", len(keys))
	}
	if raw := f.blobs.Raw(keys[0]); bytes.Contains(raw, []byte(content)) || bytes.Contains(raw, []byte("John Doe")) {
		t.Error("blob store contains plaintext")
	}

	rec, _, err := f.repo.Document(t.Context(), doc.ID, alice.UserID)
	if err != nil {
		t.Fatalf("Document: %v", err)
	}
	if bytes.Contains(rec.NameCiphertext, []byte("Confidential")) {
		t.Error("repository contains the plaintext name")
	}
}

func TestCiphertextIsBoundToVersion(t *testing.T) {
	f := newFixture(t)
	alice := f.user("alice")
	doc := f.upload(alice, "Doc", "version one")
	if _, err := f.svc.AddVersion(t.Context(), alice, doc.ID, []byte("version two")); err != nil {
		t.Fatalf("AddVersion: %v", err)
	}

	v1, _ := f.repo.Version(t.Context(), doc.ID, 1)
	v2, _ := f.repo.Version(t.Context(), doc.ID, 2)
	// An attacker with storage access swaps the ciphertext of version 2
	// with version 1's: authentication must fail instead of serving it.
	if err := f.blobs.Put(t.Context(), v2.BlobKey, f.blobs.Raw(v1.BlobKey)); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.Download(t.Context(), alice, doc.ID, 2); !errors.Is(err, envelope.ErrDecrypt) {
		t.Errorf("swapped ciphertext: err = %v, want %v", err, envelope.ErrDecrypt)
	}
}

func TestVersions(t *testing.T) {
	f := newFixture(t)
	alice := f.user("alice")
	doc := f.upload(alice, "Doc", "first")

	v, err := f.svc.AddVersion(t.Context(), alice, doc.ID, []byte("second"))
	if err != nil || v.Number != 2 {
		t.Fatalf("AddVersion = %+v, %v", v, err)
	}

	for n, want := range map[int]string{0: "second", 1: "first", 2: "second"} {
		got, err := f.svc.Download(t.Context(), alice, doc.ID, n)
		if err != nil || string(got.Data) != want {
			t.Errorf("Download(version %d) = %q, %v; want %q", n, got.Data, err, want)
		}
	}
	if _, err := f.svc.Download(t.Context(), alice, doc.ID, 3); !errors.Is(err, documents.ErrNotFound) {
		t.Errorf("missing version: err = %v", err)
	}

	versions, err := f.svc.Versions(t.Context(), alice, doc.ID)
	if err != nil || len(versions) != 2 || versions[0].Number != 1 || versions[1].Number != 2 {
		t.Errorf("Versions = %+v, %v", versions, err)
	}
}

func TestPermissions(t *testing.T) {
	f := newFixture(t)
	ctx := t.Context()
	owner, viewer, editor, stranger := f.user("owner"), f.user("viewer"), f.user("editor"), f.user("stranger")
	doc := f.upload(owner, "Shared", "content")

	if err := f.svc.Share(ctx, owner, doc.ID, "viewer", documents.RoleViewer); err != nil {
		t.Fatalf("Share viewer: %v", err)
	}
	if err := f.svc.Share(ctx, owner, doc.ID, "EDITOR", documents.RoleEditor); err != nil {
		t.Fatalf("Share editor: %v", err)
	}

	// Stranger: the document does not exist for them.
	if _, err := f.svc.Get(ctx, stranger, doc.ID); !errors.Is(err, documents.ErrNotFound) {
		t.Errorf("stranger Get: err = %v, want ErrNotFound", err)
	}
	if _, err := f.svc.Download(ctx, stranger, doc.ID, 0); !errors.Is(err, documents.ErrNotFound) {
		t.Errorf("stranger Download: err = %v, want ErrNotFound", err)
	}

	// Viewer: read only.
	if _, err := f.svc.Download(ctx, viewer, doc.ID, 0); err != nil {
		t.Errorf("viewer Download: %v", err)
	}
	if _, err := f.svc.AddVersion(ctx, viewer, doc.ID, []byte("x")); !errors.Is(err, documents.ErrForbidden) {
		t.Errorf("viewer AddVersion: err = %v, want ErrForbidden", err)
	}
	if _, err := f.svc.Rename(ctx, viewer, doc.ID, "x"); !errors.Is(err, documents.ErrForbidden) {
		t.Errorf("viewer Rename: err = %v, want ErrForbidden", err)
	}

	// Editor: can change content and name, cannot delete or share.
	if _, err := f.svc.AddVersion(ctx, editor, doc.ID, []byte("edited")); err != nil {
		t.Errorf("editor AddVersion: %v", err)
	}
	if _, err := f.svc.Rename(ctx, editor, doc.ID, "Renamed"); err != nil {
		t.Errorf("editor Rename: %v", err)
	}
	if err := f.svc.Delete(ctx, editor, doc.ID); !errors.Is(err, documents.ErrForbidden) {
		t.Errorf("editor Delete: err = %v, want ErrForbidden", err)
	}
	if err := f.svc.Share(ctx, editor, doc.ID, "stranger", documents.RoleViewer); !errors.Is(err, documents.ErrForbidden) {
		t.Errorf("editor Share: err = %v, want ErrForbidden", err)
	}

	perms, err := f.svc.Permissions(ctx, owner, doc.ID)
	if err != nil || len(perms) != 3 {
		t.Fatalf("Permissions = %+v, %v", perms, err)
	}

	// Revoked access disappears immediately.
	if err := f.svc.Unshare(ctx, owner, doc.ID, "viewer"); err != nil {
		t.Fatalf("Unshare: %v", err)
	}
	if _, err := f.svc.Get(ctx, viewer, doc.ID); !errors.Is(err, documents.ErrNotFound) {
		t.Errorf("Get after unshare: err = %v, want ErrNotFound", err)
	}
}

func TestShareValidation(t *testing.T) {
	f := newFixture(t)
	ctx := t.Context()
	owner := f.user("owner")
	doc := f.upload(owner, "Doc", "content")

	if err := f.svc.Share(ctx, owner, doc.ID, "owner", documents.RoleViewer); !errors.Is(err, documents.ErrInvalidArgument) {
		t.Errorf("share with self: err = %v", err)
	}
	if err := f.svc.Share(ctx, owner, doc.ID, "ghost", documents.RoleViewer); !errors.Is(err, auth.ErrUserNotFound) {
		t.Errorf("share with unknown user: err = %v", err)
	}
	if err := f.svc.Unshare(ctx, owner, doc.ID, "owner"); !errors.Is(err, documents.ErrInvalidArgument) {
		t.Errorf("unshare owner: err = %v", err)
	}
	if _, err := documents.ParseShareRole("owner"); !errors.Is(err, documents.ErrInvalidArgument) {
		t.Errorf("ParseShareRole(owner): err = %v", err)
	}
}

func TestDeleteShredsDocument(t *testing.T) {
	f := newFixture(t)
	ctx := t.Context()
	owner, viewer := f.user("owner"), f.user("viewer")
	doc := f.upload(owner, "To delete", "content")
	if _, err := f.svc.AddVersion(ctx, owner, doc.ID, []byte("v2")); err != nil {
		t.Fatal(err)
	}
	_ = f.svc.Share(ctx, owner, doc.ID, "viewer", documents.RoleViewer)

	v1, _ := f.repo.Version(ctx, doc.ID, 1)
	if err := f.svc.Delete(ctx, owner, doc.ID); err != nil {
		t.Fatalf("Delete: %v", err)
	}

	if f.repo.MetaKey(doc.ID) != nil {
		t.Error("metadata key survived deletion")
	}
	if _, err := f.repo.Version(ctx, doc.ID, 1); !errors.Is(err, documents.ErrNotFound) {
		t.Error("version data key survived deletion")
	}
	if len(f.blobs.Keys()) != 0 {
		t.Errorf("blobs left after deletion: %v", f.blobs.Keys())
	}
	if v1.BlobKey == "" {
		t.Fatal("precondition: version 1 had a blob")
	}
	for _, actor := range []documents.Actor{owner, viewer} {
		if _, err := f.svc.Download(ctx, actor, doc.ID, 0); !errors.Is(err, documents.ErrNotFound) {
			t.Errorf("Download after delete: err = %v, want ErrNotFound", err)
		}
	}
}

func TestAuditLog(t *testing.T) {
	f := newFixture(t)
	ctx := t.Context()
	owner, viewer := f.user("owner"), f.user("viewer")
	doc := f.upload(owner, "Audited", "content")
	_ = f.svc.Share(ctx, owner, doc.ID, "viewer", documents.RoleViewer)
	_, _ = f.svc.Download(ctx, viewer, doc.ID, 0)
	_, _ = f.svc.AddVersion(ctx, viewer, doc.ID, []byte("denied")) // denied

	events, err := f.svc.AuditLog(ctx, owner, doc.ID)
	if err != nil {
		t.Fatalf("AuditLog: %v", err)
	}
	got := make([]string, 0, len(events))
	for _, e := range events {
		got = append(got, e.Action+":"+e.Outcome)
	}
	want := []string{
		"document.version.create:denied",
		"document.download:success",
		"document.share:success",
		"document.create:success",
	}
	if !slices.Equal(got, want) {
		t.Errorf("audit events = %v, want %v", got, want)
	}
	if events[1].ActorID != viewer.UserID || events[1].RequestID != "req-viewer" || events[1].ClientIP != "203.0.113.1" {
		t.Errorf("download event = %+v", events[1])
	}

	if _, err := f.svc.AuditLog(ctx, viewer, doc.ID); !errors.Is(err, documents.ErrForbidden) {
		t.Errorf("viewer AuditLog: err = %v, want ErrForbidden", err)
	}
}

func TestListPagination(t *testing.T) {
	f := newFixture(t)
	ctx := t.Context()
	alice, bob := f.user("alice"), f.user("bob")
	for _, name := range []string{"a", "b", "c"} {
		f.upload(alice, name, "content "+name)
	}
	f.upload(bob, "bob's", "content")

	page1, next, err := f.svc.List(ctx, alice, uuid.Nil, 2)
	if err != nil || len(page1) != 2 || next == uuid.Nil {
		t.Fatalf("page 1 = %d docs, next %v, err %v", len(page1), next, err)
	}
	if page1[0].Name != "c" || page1[1].Name != "b" {
		t.Errorf("page 1 order = %q, %q; want newest first", page1[0].Name, page1[1].Name)
	}
	page2, next, err := f.svc.List(ctx, alice, next, 2)
	if err != nil || len(page2) != 1 || page2[0].Name != "a" || next != uuid.Nil {
		t.Errorf("page 2 = %+v, next %v, err %v", page2, next, err)
	}

	if _, _, err := f.svc.List(ctx, alice, uuid.Nil, 0); !errors.Is(err, documents.ErrInvalidArgument) {
		t.Errorf("limit 0: err = %v", err)
	}
}

func TestRename(t *testing.T) {
	f := newFixture(t)
	alice := f.user("alice")
	doc := f.upload(alice, "Old", "content")

	if _, err := f.svc.Rename(t.Context(), alice, doc.ID, "  New name  "); err != nil {
		t.Fatalf("Rename: %v", err)
	}
	got, err := f.svc.Get(t.Context(), alice, doc.ID)
	if err != nil || got.Name != "New name" {
		t.Errorf("Get after rename = %q, %v", got.Name, err)
	}
}

func TestUploadValidation(t *testing.T) {
	f := newFixture(t)
	alice := f.user("alice")
	tests := map[string]struct{ name, content string }{
		"empty name":    {"  ", "content"},
		"long name":     {strings.Repeat("x", 256), "content"},
		"control chars": {"bad\x00name", "content"},
		"empty file":    {"ok", ""},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := f.svc.Upload(t.Context(), alice, tt.name, []byte(tt.content)); !errors.Is(err, documents.ErrInvalidArgument) {
				t.Errorf("err = %v, want ErrInvalidArgument", err)
			}
		})
	}
	if len(f.blobs.Keys()) != 0 {
		t.Error("rejected uploads left blobs behind")
	}
}
