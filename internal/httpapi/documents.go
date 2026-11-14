package httpapi

import (
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"strconv"
	"time"

	"github.com/google/uuid"

	"github.com/dNertyco/secretum/internal/auth"
	"github.com/dNertyco/secretum/internal/documents"
)

const (
	defaultListLimit = 50
	maxNameFieldLen  = 4 << 10
	multipartSlack   = 1 << 20
)

type documentResponse struct {
	ID             uuid.UUID `json:"id"`
	Name           string    `json:"name"`
	OwnerID        uuid.UUID `json:"owner_id"`
	Role           string    `json:"role"`
	CurrentVersion int       `json:"current_version"`
	Size           int64     `json:"size"`
	ContentType    string    `json:"content_type"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
}

func toDocumentResponse(d documents.Document) documentResponse {
	return documentResponse{
		ID: d.ID, Name: d.Name, OwnerID: d.OwnerID, Role: string(d.Role),
		CurrentVersion: d.CurrentVersion, Size: d.Size, ContentType: d.ContentType,
		CreatedAt: d.CreatedAt, UpdatedAt: d.UpdatedAt,
	}
}

type versionResponse struct {
	Number      int       `json:"number"`
	Size        int64     `json:"size"`
	ContentType string    `json:"content_type"`
	CreatedBy   uuid.UUID `json:"created_by"`
	CreatedAt   time.Time `json:"created_at"`
}

func toVersionResponse(v documents.Version) versionResponse {
	return versionResponse{Number: v.Number, Size: v.Size, ContentType: v.ContentType, CreatedBy: v.CreatedBy, CreatedAt: v.CreatedAt}
}

type permissionResponse struct {
	UserID    uuid.UUID `json:"user_id"`
	Username  string    `json:"username"`
	Role      string    `json:"role"`
	GrantedAt time.Time `json:"granted_at"`
}

type auditEventResponse struct {
	ID         int64      `json:"id"`
	OccurredAt time.Time  `json:"occurred_at"`
	ActorID    *uuid.UUID `json:"actor_id"`
	Action     string     `json:"action"`
	Outcome    string     `json:"outcome"`
	RequestID  string     `json:"request_id"`
	ClientIP   string     `json:"client_ip"`
}

type listResponse[T any] struct {
	Items     []T        `json:"items"`
	NextAfter *uuid.UUID `json:"next_after,omitempty"`
}

func (a *api) actor(r *http.Request) documents.Actor {
	return documents.Actor{
		UserID:    userFrom(r.Context()).ID,
		RequestID: RequestIDFrom(r.Context()),
		ClientIP:  clientIP(r),
	}
}

func (a *api) documentID(w http.ResponseWriter, r *http.Request) (uuid.UUID, bool) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		// Malformed IDs are indistinguishable from missing documents.
		a.writeError(w, http.StatusNotFound, "not_found", documents.ErrNotFound.Error())
		return uuid.Nil, false
	}
	return id, true
}

// domainError maps service errors to HTTP responses.
func (a *api) domainError(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, documents.ErrNotFound):
		a.writeError(w, http.StatusNotFound, "not_found", documents.ErrNotFound.Error())
	case errors.Is(err, documents.ErrForbidden):
		a.writeError(w, http.StatusForbidden, "forbidden", err.Error())
	case errors.Is(err, documents.ErrConflict):
		a.writeError(w, http.StatusConflict, "conflict", err.Error())
	case errors.Is(err, documents.ErrInvalidArgument):
		a.writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
	case errors.Is(err, auth.ErrUserNotFound):
		a.writeError(w, http.StatusNotFound, "user_not_found", err.Error())
	default:
		a.internalError(w, r, err)
	}
}

type upload struct {
	name     string
	filename string
	data     []byte
}

var errUploadTooLarge = errors.New("file is too large")

// readUpload streams a multipart/form-data body with a "file" part and an
// optional "name" field, enforcing the upload size limit while reading.
func (a *api) readUpload(w http.ResponseWriter, r *http.Request) (upload, error) {
	r.Body = http.MaxBytesReader(w, r.Body, a.MaxUploadBytes+multipartSlack)
	mr, err := r.MultipartReader()
	if err != nil {
		return upload{}, fmt.Errorf("%w: expected multipart/form-data", documents.ErrInvalidArgument)
	}

	var u upload
	var haveFile bool
	for {
		part, err := mr.NextPart()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return upload{}, wrapReadError(err)
		}
		switch part.FormName() {
		case "file":
			data, err := io.ReadAll(io.LimitReader(part, a.MaxUploadBytes+1))
			if err != nil {
				return upload{}, wrapReadError(err)
			}
			if int64(len(data)) > a.MaxUploadBytes {
				return upload{}, errUploadTooLarge
			}
			u.data, u.filename, haveFile = data, part.FileName(), true
		case "name":
			b, err := io.ReadAll(io.LimitReader(part, maxNameFieldLen))
			if err != nil {
				return upload{}, wrapReadError(err)
			}
			u.name = string(b)
		}
		_ = part.Close()
	}
	if !haveFile {
		return upload{}, fmt.Errorf("%w: missing \"file\" part", documents.ErrInvalidArgument)
	}
	return u, nil
}

func wrapReadError(err error) error {
	var tooLarge *http.MaxBytesError
	if errors.As(err, &tooLarge) {
		return errUploadTooLarge
	}
	return fmt.Errorf("%w: malformed multipart body", documents.ErrInvalidArgument)
}

func (a *api) uploadError(w http.ResponseWriter, r *http.Request, err error) {
	if errors.Is(err, errUploadTooLarge) {
		a.writeError(w, http.StatusRequestEntityTooLarge, "too_large",
			fmt.Sprintf("file exceeds the %d byte limit", a.MaxUploadBytes))
		return
	}
	a.domainError(w, r, err)
}

func (a *api) createDocument(w http.ResponseWriter, r *http.Request) {
	u, err := a.readUpload(w, r)
	if err != nil {
		a.uploadError(w, r, err)
		return
	}
	name := u.name
	if name == "" {
		// Automatic naming from content is planned; until then the original
		// file name is used.
		name = u.filename
	}
	doc, err := a.Documents.Upload(r.Context(), a.actor(r), name, u.data)
	if err != nil {
		a.domainError(w, r, err)
		return
	}
	w.Header().Set("Location", "/v1/documents/"+doc.ID.String())
	a.writeJSON(w, http.StatusCreated, toDocumentResponse(doc))
}

func (a *api) listDocuments(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	limit := defaultListLimit
	if v := q.Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil {
			a.writeError(w, http.StatusBadRequest, "invalid_request", "limit must be an integer")
			return
		}
		limit = n
	}
	after := uuid.Nil
	if v := q.Get("after"); v != "" {
		id, err := uuid.Parse(v)
		if err != nil {
			a.writeError(w, http.StatusBadRequest, "invalid_request", "after must be a document id")
			return
		}
		after = id
	}

	docs, next, err := a.Documents.List(r.Context(), a.actor(r), after, limit)
	if err != nil {
		a.domainError(w, r, err)
		return
	}
	resp := listResponse[documentResponse]{Items: make([]documentResponse, 0, len(docs))}
	for _, d := range docs {
		resp.Items = append(resp.Items, toDocumentResponse(d))
	}
	if next != uuid.Nil {
		resp.NextAfter = &next
	}
	a.writeJSON(w, http.StatusOK, resp)
}

func (a *api) getDocument(w http.ResponseWriter, r *http.Request) {
	id, ok := a.documentID(w, r)
	if !ok {
		return
	}
	doc, err := a.Documents.Get(r.Context(), a.actor(r), id)
	if err != nil {
		a.domainError(w, r, err)
		return
	}
	a.writeJSON(w, http.StatusOK, toDocumentResponse(doc))
}

func (a *api) renameDocument(w http.ResponseWriter, r *http.Request) {
	id, ok := a.documentID(w, r)
	if !ok {
		return
	}
	var req struct {
		Name string `json:"name"`
	}
	if err := decodeJSON(w, r, &req); err != nil {
		a.writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	doc, err := a.Documents.Rename(r.Context(), a.actor(r), id, req.Name)
	if err != nil {
		a.domainError(w, r, err)
		return
	}
	a.writeJSON(w, http.StatusOK, toDocumentResponse(doc))
}

func (a *api) deleteDocument(w http.ResponseWriter, r *http.Request) {
	id, ok := a.documentID(w, r)
	if !ok {
		return
	}
	if err := a.Documents.Delete(r.Context(), a.actor(r), id); err != nil {
		a.domainError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (a *api) downloadDocument(w http.ResponseWriter, r *http.Request) {
	id, ok := a.documentID(w, r)
	if !ok {
		return
	}
	version := 0
	if v := r.URL.Query().Get("version"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n <= 0 {
			a.writeError(w, http.StatusBadRequest, "invalid_request", "version must be a positive integer")
			return
		}
		version = n
	}

	c, err := a.Documents.Download(r.Context(), a.actor(r), id, version)
	if err != nil {
		a.domainError(w, r, err)
		return
	}

	h := w.Header()
	h.Set("Content-Type", c.Version.ContentType)
	h.Set("Content-Length", strconv.Itoa(len(c.Data)))
	// Always download, never render: uploaded HTML or SVG must not execute
	// in the API's origin.
	h.Set("Content-Disposition", mime.FormatMediaType("attachment", map[string]string{"filename": c.Document.Name}))
	h.Set("Content-Security-Policy", "sandbox")
	h.Set("X-Document-Version", strconv.Itoa(c.Version.Number))
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write(c.Data); err != nil {
		a.Logger.WarnContext(r.Context(), "write document content", "err", err)
	}
}

func (a *api) createVersion(w http.ResponseWriter, r *http.Request) {
	id, ok := a.documentID(w, r)
	if !ok {
		return
	}
	u, err := a.readUpload(w, r)
	if err != nil {
		a.uploadError(w, r, err)
		return
	}
	v, err := a.Documents.AddVersion(r.Context(), a.actor(r), id, u.data)
	if err != nil {
		a.domainError(w, r, err)
		return
	}
	a.writeJSON(w, http.StatusCreated, toVersionResponse(v))
}

func (a *api) listVersions(w http.ResponseWriter, r *http.Request) {
	id, ok := a.documentID(w, r)
	if !ok {
		return
	}
	versions, err := a.Documents.Versions(r.Context(), a.actor(r), id)
	if err != nil {
		a.domainError(w, r, err)
		return
	}
	resp := listResponse[versionResponse]{Items: make([]versionResponse, 0, len(versions))}
	for _, v := range versions {
		resp.Items = append(resp.Items, toVersionResponse(v))
	}
	a.writeJSON(w, http.StatusOK, resp)
}

func (a *api) listPermissions(w http.ResponseWriter, r *http.Request) {
	id, ok := a.documentID(w, r)
	if !ok {
		return
	}
	perms, err := a.Documents.Permissions(r.Context(), a.actor(r), id)
	if err != nil {
		a.domainError(w, r, err)
		return
	}
	resp := listResponse[permissionResponse]{Items: make([]permissionResponse, 0, len(perms))}
	for _, p := range perms {
		resp.Items = append(resp.Items, permissionResponse{UserID: p.UserID, Username: p.Username, Role: string(p.Role), GrantedAt: p.GrantedAt})
	}
	a.writeJSON(w, http.StatusOK, resp)
}

func (a *api) putPermission(w http.ResponseWriter, r *http.Request) {
	id, ok := a.documentID(w, r)
	if !ok {
		return
	}
	var req struct {
		Role string `json:"role"`
	}
	if err := decodeJSON(w, r, &req); err != nil {
		a.writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	role, err := documents.ParseShareRole(req.Role)
	if err != nil {
		a.domainError(w, r, err)
		return
	}
	if err := a.Documents.Share(r.Context(), a.actor(r), id, r.PathValue("username"), role); err != nil {
		a.domainError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (a *api) deletePermission(w http.ResponseWriter, r *http.Request) {
	id, ok := a.documentID(w, r)
	if !ok {
		return
	}
	if err := a.Documents.Unshare(r.Context(), a.actor(r), id, r.PathValue("username")); err != nil {
		a.domainError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (a *api) auditLog(w http.ResponseWriter, r *http.Request) {
	id, ok := a.documentID(w, r)
	if !ok {
		return
	}
	events, err := a.Documents.AuditLog(r.Context(), a.actor(r), id)
	if err != nil {
		a.domainError(w, r, err)
		return
	}
	resp := listResponse[auditEventResponse]{Items: make([]auditEventResponse, 0, len(events))}
	for _, e := range events {
		item := auditEventResponse{
			ID: e.ID, OccurredAt: e.OccurredAt, Action: e.Action, Outcome: e.Outcome,
			RequestID: e.RequestID, ClientIP: e.ClientIP,
		}
		if e.ActorID != uuid.Nil {
			item.ActorID = &e.ActorID
		}
		resp.Items = append(resp.Items, item)
	}
	a.writeJSON(w, http.StatusOK, resp)
}
