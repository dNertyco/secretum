package doctest

import (
	"bytes"
	"errors"
	"slices"
	"strconv"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/dNertyco/secretum/internal/auth"
	"github.com/dNertyco/secretum/internal/documents"
	"github.com/dNertyco/secretum/internal/envelope"
)

// Setup returns a fresh, empty repository and the user repository it uses.
type Setup func(t *testing.T) (documents.Repository, auth.UserRepository)

// RunRepositoryContract checks that a documents.Repository implementation
// behaves as the service expects. Every implementation must pass it.
func RunRepositoryContract(t *testing.T, setup Setup) {
	t.Run("CreateAndGet", func(t *testing.T) { testCreateAndGet(t, setup) })
	t.Run("List", func(t *testing.T) { testList(t, setup) })
	t.Run("Versions", func(t *testing.T) { testVersions(t, setup) })
	t.Run("Rename", func(t *testing.T) { testRename(t, setup) })
	t.Run("Permissions", func(t *testing.T) { testPermissions(t, setup) })
	t.Run("Shred", func(t *testing.T) { testShred(t, setup) })
	t.Run("Audit", func(t *testing.T) { testAudit(t, setup) })
}

var baseTime = time.Date(2026, 11, 14, 12, 0, 0, 0, time.UTC)

func newUser(t *testing.T, users auth.UserRepository, name string) uuid.UUID {
	t.Helper()
	u := auth.User{ID: uuid.Must(uuid.NewV7()), Username: name, PasswordHash: "x", CreatedAt: baseTime}
	if err := users.CreateUser(t.Context(), u); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	return u.ID
}

func newDoc(t *testing.T, repo documents.Repository, owner uuid.UUID) (documents.DocumentRecord, documents.VersionRecord) {
	t.Helper()
	id := uuid.Must(uuid.NewV7())
	d := documents.DocumentRecord{
		ID:             id,
		OwnerID:        owner,
		NameCiphertext: []byte("name-ct-" + id.String()),
		MetaKey:        envelope.WrappedKey{KEKID: "k1", Ciphertext: []byte("meta-key")},
		CurrentVersion: 1,
		CreatedAt:      baseTime,
		UpdatedAt:      baseTime,
	}
	v := newVersion(owner, id, 1)
	if err := repo.CreateDocument(t.Context(), d, v); err != nil {
		t.Fatalf("CreateDocument: %v", err)
	}
	return d, v
}

func newVersion(actor, doc uuid.UUID, n int) documents.VersionRecord {
	return documents.VersionRecord{
		DocumentID:  doc,
		Number:      n,
		BlobKey:     "documents/" + doc.String() + "/" + uuid.NewString(),
		Key:         envelope.WrappedKey{KEKID: "k1", Ciphertext: []byte("wrapped-dek-" + strconv.Itoa(n))},
		Size:        int64(100 * n),
		ContentType: "application/pdf",
		CreatedBy:   actor,
		CreatedAt:   baseTime.Add(time.Duration(n) * time.Minute),
	}
}

func testCreateAndGet(t *testing.T, setup Setup) {
	repo, users := setup(t)
	ctx := t.Context()
	owner, other := newUser(t, users, "owner"), newUser(t, users, "other")
	d, v := newDoc(t, repo, owner)

	got, role, err := repo.Document(ctx, d.ID, owner)
	if err != nil {
		t.Fatalf("Document: %v", err)
	}
	if role != documents.RoleOwner {
		t.Errorf("owner role = %q", role)
	}
	if got.ID != d.ID || got.OwnerID != owner || !bytes.Equal(got.NameCiphertext, d.NameCiphertext) ||
		got.MetaKey.KEKID != "k1" || !bytes.Equal(got.MetaKey.Ciphertext, d.MetaKey.Ciphertext) ||
		got.CurrentVersion != 1 || !got.CreatedAt.Equal(baseTime) {
		t.Errorf("Document = %+v, want %+v", got, d)
	}
	if got.Size != v.Size || got.ContentType != v.ContentType {
		t.Errorf("current version fields = %d/%q, want %d/%q", got.Size, got.ContentType, v.Size, v.ContentType)
	}

	if _, role, err := repo.Document(ctx, d.ID, other); err != nil || role != "" {
		t.Errorf("non-member: role = %q, err = %v; want empty role", role, err)
	}
	if _, _, err := repo.Document(ctx, uuid.New(), owner); !errors.Is(err, documents.ErrNotFound) {
		t.Errorf("missing document: err = %v", err)
	}
}

func testList(t *testing.T, setup Setup) {
	repo, users := setup(t)
	ctx := t.Context()
	alice, bob := newUser(t, users, "alice"), newUser(t, users, "bob")
	var ids []uuid.UUID
	for range 3 {
		d, _ := newDoc(t, repo, alice)
		ids = append(ids, d.ID)
	}
	newDoc(t, repo, bob)

	page, err := repo.ListDocuments(ctx, alice, uuid.Nil, 2)
	if err != nil || len(page) != 2 {
		t.Fatalf("ListDocuments = %d, %v", len(page), err)
	}
	if page[0].ID != ids[2] || page[1].ID != ids[1] || page[0].Role != documents.RoleOwner {
		t.Errorf("page order/roles wrong: %v, %v", page[0].ID, page[1].ID)
	}
	rest, err := repo.ListDocuments(ctx, alice, page[1].ID, 10)
	if err != nil || len(rest) != 1 || rest[0].ID != ids[0] {
		t.Errorf("second page = %+v, %v", rest, err)
	}
}

func testVersions(t *testing.T, setup Setup) {
	repo, users := setup(t)
	ctx := t.Context()
	owner := newUser(t, users, "owner")
	d, v1 := newDoc(t, repo, owner)

	v2 := newVersion(owner, d.ID, 2)
	if err := repo.AddVersion(ctx, v2); err != nil {
		t.Fatalf("AddVersion: %v", err)
	}
	stale := newVersion(owner, d.ID, 2)
	if err := repo.AddVersion(ctx, stale); !errors.Is(err, documents.ErrConflict) {
		t.Errorf("stale version: err = %v, want ErrConflict", err)
	}

	got, _, _ := repo.Document(ctx, d.ID, owner)
	if got.CurrentVersion != 2 || got.Size != v2.Size {
		t.Errorf("current version = %d (size %d), want 2", got.CurrentVersion, got.Size)
	}

	gotV1, err := repo.Version(ctx, d.ID, 1)
	if err != nil || gotV1.BlobKey != v1.BlobKey || !bytes.Equal(gotV1.Key.Ciphertext, v1.Key.Ciphertext) || gotV1.CreatedBy != owner {
		t.Errorf("Version(1) = %+v, %v", gotV1, err)
	}
	if _, err := repo.Version(ctx, d.ID, 3); !errors.Is(err, documents.ErrNotFound) {
		t.Errorf("Version(3): err = %v", err)
	}

	all, err := repo.Versions(ctx, d.ID)
	if err != nil || len(all) != 2 || all[0].Number != 1 || all[1].Number != 2 {
		t.Errorf("Versions = %+v, %v", all, err)
	}
}

func testRename(t *testing.T, setup Setup) {
	repo, users := setup(t)
	ctx := t.Context()
	owner := newUser(t, users, "owner")
	d, _ := newDoc(t, repo, owner)

	at := baseTime.Add(time.Hour)
	if err := repo.Rename(ctx, d.ID, []byte("new-name-ct"), at); err != nil {
		t.Fatalf("Rename: %v", err)
	}
	got, _, _ := repo.Document(ctx, d.ID, owner)
	if string(got.NameCiphertext) != "new-name-ct" || !got.UpdatedAt.Equal(at) {
		t.Errorf("after rename: %q, %v", got.NameCiphertext, got.UpdatedAt)
	}
}

func testPermissions(t *testing.T, setup Setup) {
	repo, users := setup(t)
	ctx := t.Context()
	owner, bob := newUser(t, users, "owner"), newUser(t, users, "bob")
	d, _ := newDoc(t, repo, owner)

	if err := repo.SetPermission(ctx, d.ID, bob, documents.RoleViewer, owner, baseTime.Add(time.Minute)); err != nil {
		t.Fatalf("SetPermission: %v", err)
	}
	if err := repo.SetPermission(ctx, d.ID, bob, documents.RoleEditor, owner, baseTime.Add(2*time.Minute)); err != nil {
		t.Fatalf("SetPermission upsert: %v", err)
	}
	if _, role, _ := repo.Document(ctx, d.ID, bob); role != documents.RoleEditor {
		t.Errorf("bob role = %q, want editor", role)
	}
	// The owner's role cannot be downgraded through SetPermission.
	_ = repo.SetPermission(ctx, d.ID, owner, documents.RoleViewer, owner, baseTime)
	if _, role, _ := repo.Document(ctx, d.ID, owner); role != documents.RoleOwner {
		t.Errorf("owner role = %q after SetPermission, want owner", role)
	}

	perms, err := repo.Permissions(ctx, d.ID)
	if err != nil || len(perms) != 2 {
		t.Fatalf("Permissions = %+v, %v", perms, err)
	}
	names := []string{perms[0].Username, perms[1].Username}
	slices.Sort(names)
	if !slices.Equal(names, []string{"bob", "owner"}) {
		t.Errorf("permission usernames = %v", names)
	}

	if err := repo.RemovePermission(ctx, d.ID, owner); !errors.Is(err, documents.ErrNotFound) {
		t.Errorf("remove owner: err = %v, want ErrNotFound", err)
	}
	if err := repo.RemovePermission(ctx, d.ID, bob); err != nil {
		t.Fatalf("RemovePermission: %v", err)
	}
	if err := repo.RemovePermission(ctx, d.ID, bob); !errors.Is(err, documents.ErrNotFound) {
		t.Errorf("remove twice: err = %v, want ErrNotFound", err)
	}
	if _, role, _ := repo.Document(ctx, d.ID, bob); role != "" {
		t.Errorf("bob role after removal = %q", role)
	}
}

func testShred(t *testing.T, setup Setup) {
	repo, users := setup(t)
	ctx := t.Context()
	owner := newUser(t, users, "owner")
	d, v1 := newDoc(t, repo, owner)
	v2 := newVersion(owner, d.ID, 2)
	if err := repo.AddVersion(ctx, v2); err != nil {
		t.Fatal(err)
	}

	keys, err := repo.Shred(ctx, d.ID, baseTime.Add(time.Hour))
	if err != nil {
		t.Fatalf("Shred: %v", err)
	}
	slices.Sort(keys)
	want := []string{v1.BlobKey, v2.BlobKey}
	slices.Sort(want)
	if !slices.Equal(keys, want) {
		t.Errorf("blob keys = %v, want %v", keys, want)
	}

	if _, _, err := repo.Document(ctx, d.ID, owner); !errors.Is(err, documents.ErrNotFound) {
		t.Errorf("Document after shred: err = %v", err)
	}
	if _, err := repo.Version(ctx, d.ID, 1); !errors.Is(err, documents.ErrNotFound) {
		t.Errorf("Version after shred: err = %v", err)
	}
	if list, _ := repo.ListDocuments(ctx, owner, uuid.Nil, 10); len(list) != 0 {
		t.Errorf("shredded document is listed")
	}
	if _, err := repo.Shred(ctx, d.ID, baseTime); !errors.Is(err, documents.ErrNotFound) {
		t.Errorf("second shred: err = %v", err)
	}
	if err := repo.AddVersion(ctx, newVersion(owner, d.ID, 3)); !errors.Is(err, documents.ErrConflict) {
		t.Errorf("AddVersion after shred: err = %v, want ErrConflict", err)
	}
}

func testAudit(t *testing.T, setup Setup) {
	repo, users := setup(t)
	ctx := t.Context()
	actor := newUser(t, users, "actor")
	doc, other := uuid.New(), uuid.New()

	for i, action := range []string{"a1", "a2", "a3"} {
		e := documents.AuditEvent{
			OccurredAt: baseTime.Add(time.Duration(i) * time.Second),
			ActorID:    actor, Action: action, DocumentID: doc,
			Outcome: documents.OutcomeSuccess, RequestID: "r", ClientIP: "198.51.100.7",
		}
		if err := repo.RecordAudit(ctx, e); err != nil {
			t.Fatalf("RecordAudit: %v", err)
		}
	}
	_ = repo.RecordAudit(ctx, documents.AuditEvent{OccurredAt: baseTime, Action: "x", DocumentID: other, Outcome: documents.OutcomeDenied})

	events, err := repo.AuditEvents(ctx, doc, 2)
	if err != nil || len(events) != 2 {
		t.Fatalf("AuditEvents = %+v, %v", events, err)
	}
	if events[0].Action != "a3" || events[1].Action != "a2" {
		t.Errorf("order = %s, %s; want newest first", events[0].Action, events[1].Action)
	}
	e := events[0]
	if e.ActorID != actor || e.ClientIP != "198.51.100.7" || e.RequestID != "r" || !e.OccurredAt.Equal(baseTime.Add(2*time.Second)) || e.ID == 0 {
		t.Errorf("event fields = %+v", e)
	}

	anon, _ := repo.AuditEvents(ctx, other, 10)
	if len(anon) != 1 || anon[0].ActorID != uuid.Nil {
		t.Errorf("event without actor = %+v", anon)
	}
}
