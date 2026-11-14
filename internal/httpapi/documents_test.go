package httpapi

import (
	"bytes"
	"fmt"
	"mime"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func (s *testServer) login(username string) string {
	s.t.Helper()
	creds := credentials{Username: username, Password: "a-long-enough-password"}
	if rec := s.do(http.MethodPost, "/v1/auth/register", creds, ""); rec.Code != http.StatusCreated {
		s.t.Fatalf("register %s: %d %s", username, rec.Code, rec.Body)
	}
	rec := s.do(http.MethodPost, "/v1/auth/login", creds, "")
	if rec.Code != http.StatusOK {
		s.t.Fatalf("login %s: %d %s", username, rec.Code, rec.Body)
	}
	return decode[tokenResponse](s.t, rec).AccessToken
}

// multipartBody builds a multipart/form-data body; an empty filename omits
// the file part.
func multipartBody(t *testing.T, name, filename, content string) (*bytes.Buffer, string) {
	t.Helper()
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	if name != "" {
		if err := mw.WriteField("name", name); err != nil {
			t.Fatal(err)
		}
	}
	if filename != "" {
		fw, err := mw.CreateFormFile("file", filename)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := fw.Write([]byte(content)); err != nil {
			t.Fatal(err)
		}
	}
	if err := mw.Close(); err != nil {
		t.Fatal(err)
	}
	return &buf, mw.FormDataContentType()
}

func (s *testServer) upload(path, token, name, filename, content string) *httptest.ResponseRecorder {
	s.t.Helper()
	body, contentType := multipartBody(s.t, name, filename, content)
	req := httptest.NewRequestWithContext(s.t.Context(), http.MethodPost, path, body)
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	s.handler.ServeHTTP(rec, req)
	return rec
}

func (s *testServer) createDocument(token, name, content string) documentResponse {
	s.t.Helper()
	rec := s.upload("/v1/documents", token, name, "scan.pdf", content)
	if rec.Code != http.StatusCreated {
		s.t.Fatalf("create document: %d %s", rec.Code, rec.Body)
	}
	return decode[documentResponse](s.t, rec)
}

func TestDocumentLifecycle(t *testing.T) {
	s := newTestServer(t)
	alice := s.login("alice")

	doc := s.createDocument(alice, "Report 123", "first version")
	if doc.Name != "Report 123" || doc.Role != "owner" || doc.CurrentVersion != 1 {
		t.Fatalf("created document = %+v", doc)
	}
	path := "/v1/documents/" + doc.ID.String()

	rec := s.do(http.MethodGet, path+"/content", nil, alice)
	if rec.Code != http.StatusOK || rec.Body.String() != "first version" {
		t.Fatalf("download: %d %q", rec.Code, rec.Body)
	}
	_, params, err := mime.ParseMediaType(rec.Header().Get("Content-Disposition"))
	if err != nil || params["filename"] != "Report 123" {
		t.Errorf("Content-Disposition = %q", rec.Header().Get("Content-Disposition"))
	}
	if rec.Header().Get("Content-Security-Policy") != "sandbox" || rec.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Error("download is missing security headers")
	}

	rec = s.upload(path+"/versions", alice, "", "v2.pdf", "second version")
	if rec.Code != http.StatusCreated || decode[versionResponse](t, rec).Number != 2 {
		t.Fatalf("create version: %d %s", rec.Code, rec.Body)
	}
	if rec := s.do(http.MethodGet, path+"/content?version=1", nil, alice); rec.Body.String() != "first version" {
		t.Errorf("version 1 = %q", rec.Body)
	}
	if rec := s.do(http.MethodGet, path+"/content", nil, alice); rec.Header().Get("X-Document-Version") != "2" {
		t.Errorf("current version header = %q", rec.Header().Get("X-Document-Version"))
	}
	if versions := decode[listResponse[versionResponse]](t, s.do(http.MethodGet, path+"/versions", nil, alice)); len(versions.Items) != 2 {
		t.Errorf("versions = %+v", versions)
	}

	rec = s.do(http.MethodPatch, path, map[string]string{"name": "Renamed"}, alice)
	if rec.Code != http.StatusOK || decode[documentResponse](t, rec).Name != "Renamed" {
		t.Fatalf("rename: %d %s", rec.Code, rec.Body)
	}

	if rec := s.do(http.MethodDelete, path, nil, alice); rec.Code != http.StatusNoContent {
		t.Fatalf("delete: %d %s", rec.Code, rec.Body)
	}
	assertError(t, s.do(http.MethodGet, path, nil, alice), http.StatusNotFound, "not_found")
	if len(s.blobs.Keys()) != 0 {
		t.Errorf("blobs left after delete: %v", s.blobs.Keys())
	}
}

func TestDocumentNameFallsBackToFilename(t *testing.T) {
	s := newTestServer(t)
	alice := s.login("alice")
	rec := s.upload("/v1/documents", alice, "", "scan_0042.pdf", "content")
	if rec.Code != http.StatusCreated || decode[documentResponse](t, rec).Name != "scan_0042.pdf" {
		t.Fatalf("create: %d %s", rec.Code, rec.Body)
	}
}

func TestUploadErrors(t *testing.T) {
	s := newTestServer(t)
	alice := s.login("alice")

	assertError(t, s.upload("/v1/documents", alice, "No file", "", ""), http.StatusBadRequest, "invalid_request")
	assertError(t, s.upload("/v1/documents", alice, "Empty", "e.txt", ""), http.StatusBadRequest, "invalid_request")
	assertError(t, s.upload("/v1/documents", alice, "Big", "big.bin", strings.Repeat("x", 2<<10)),
		http.StatusRequestEntityTooLarge, "too_large")
	assertError(t, s.do(http.MethodPost, "/v1/documents", map[string]string{"name": "json"}, alice), http.StatusBadRequest, "invalid_request")
	assertError(t, s.upload("/v1/documents", "", "x", "x.txt", "x"), http.StatusUnauthorized, "unauthenticated")
}

func TestSharingAndAccessControl(t *testing.T) {
	s := newTestServer(t)
	alice, bob, carol := s.login("alice"), s.login("bob"), s.login("carol")
	doc := s.createDocument(alice, "Contract", "secret terms")
	path := "/v1/documents/" + doc.ID.String()

	// Without access the document does not exist, even for a valid user.
	assertError(t, s.do(http.MethodGet, path, nil, bob), http.StatusNotFound, "not_found")
	assertError(t, s.do(http.MethodGet, path+"/content", nil, bob), http.StatusNotFound, "not_found")
	assertError(t, s.do(http.MethodGet, "/v1/documents/not-a-uuid", nil, bob), http.StatusNotFound, "not_found")

	if rec := s.do(http.MethodPut, path+"/permissions/bob", map[string]string{"role": "viewer"}, alice); rec.Code != http.StatusNoContent {
		t.Fatalf("share: %d %s", rec.Code, rec.Body)
	}
	assertError(t, s.do(http.MethodPut, path+"/permissions/carol", map[string]string{"role": "owner"}, alice), http.StatusBadRequest, "invalid_request")
	assertError(t, s.do(http.MethodPut, path+"/permissions/ghost", map[string]string{"role": "viewer"}, alice), http.StatusNotFound, "user_not_found")

	if rec := s.do(http.MethodGet, path+"/content", nil, bob); rec.Code != http.StatusOK || rec.Body.String() != "secret terms" {
		t.Fatalf("viewer download: %d %q", rec.Code, rec.Body)
	}
	assertError(t, s.upload(path+"/versions", bob, "", "x.txt", "edit"), http.StatusForbidden, "forbidden")
	assertError(t, s.do(http.MethodDelete, path, nil, bob), http.StatusForbidden, "forbidden")
	assertError(t, s.do(http.MethodPut, path+"/permissions/carol", map[string]string{"role": "viewer"}, bob), http.StatusForbidden, "forbidden")
	assertError(t, s.do(http.MethodGet, path+"/audit", nil, bob), http.StatusForbidden, "forbidden")

	bobList := decode[listResponse[documentResponse]](t, s.do(http.MethodGet, "/v1/documents", nil, bob))
	if len(bobList.Items) != 1 || bobList.Items[0].Role != "viewer" {
		t.Errorf("bob's list = %+v", bobList)
	}
	if carolList := decode[listResponse[documentResponse]](t, s.do(http.MethodGet, "/v1/documents", nil, carol)); len(carolList.Items) != 0 {
		t.Errorf("carol sees documents she has no access to: %+v", carolList)
	}

	perms := decode[listResponse[permissionResponse]](t, s.do(http.MethodGet, path+"/permissions", nil, alice))
	if len(perms.Items) != 2 {
		t.Errorf("permissions = %+v", perms)
	}

	if rec := s.do(http.MethodDelete, path+"/permissions/bob", nil, alice); rec.Code != http.StatusNoContent {
		t.Fatalf("unshare: %d %s", rec.Code, rec.Body)
	}
	assertError(t, s.do(http.MethodGet, path+"/content", nil, bob), http.StatusNotFound, "not_found")

	audit := decode[listResponse[auditEventResponse]](t, s.do(http.MethodGet, path+"/audit", nil, alice))
	var actions []string
	for _, e := range audit.Items {
		actions = append(actions, e.Action+":"+e.Outcome)
	}
	joined := strings.Join(actions, ",")
	for _, want := range []string{"document.download:success", "document.version.create:denied", "document.delete:denied", "document.unshare:success"} {
		if !strings.Contains(joined, want) {
			t.Errorf("audit log %v is missing %s", actions, want)
		}
	}
}

func TestListDocumentsPagination(t *testing.T) {
	s := newTestServer(t)
	alice := s.login("alice")
	for i := range 3 {
		s.createDocument(alice, fmt.Sprintf("doc %d", i), "content")
	}

	page := decode[listResponse[documentResponse]](t, s.do(http.MethodGet, "/v1/documents?limit=2", nil, alice))
	if len(page.Items) != 2 || page.NextAfter == nil {
		t.Fatalf("page 1 = %+v", page)
	}
	page = decode[listResponse[documentResponse]](t, s.do(http.MethodGet, "/v1/documents?limit=2&after="+page.NextAfter.String(), nil, alice))
	if len(page.Items) != 1 || page.NextAfter != nil || page.Items[0].Name != "doc 0" {
		t.Errorf("page 2 = %+v", page)
	}

	assertError(t, s.do(http.MethodGet, "/v1/documents?limit=abc", nil, alice), http.StatusBadRequest, "invalid_request")
	assertError(t, s.do(http.MethodGet, "/v1/documents?limit=1000", nil, alice), http.StatusBadRequest, "invalid_request")
	assertError(t, s.do(http.MethodGet, "/v1/documents?after=x", nil, alice), http.StatusBadRequest, "invalid_request")
}
