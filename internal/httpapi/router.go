// Package httpapi implements the HTTP transport layer of the service.
package httpapi

import (
	"context"
	"log/slog"
	"net/http"

	"github.com/dNertyco/secretum/internal/auth"
	"github.com/dNertyco/secretum/internal/documents"
	"github.com/dNertyco/secretum/internal/ratelimit"
)

// BuildInfo describes the running binary.
type BuildInfo struct {
	Version string `json:"version"`
	Commit  string `json:"commit"`
}

// ReadinessCheck reports whether a dependency is ready to serve traffic.
type ReadinessCheck func(ctx context.Context) error

// Deps are the dependencies of the HTTP API.
type Deps struct {
	Logger            *slog.Logger
	Build             BuildInfo
	Auth              *auth.Service
	Documents         *documents.Service
	MaxUploadBytes    int64
	LoginLimiter      *ratelimit.Limiter
	AllowRegistration bool
	Readiness         map[string]ReadinessCheck
}

type api struct {
	Deps
}

// NewRouter returns the root HTTP handler with all routes and middleware.
func NewRouter(d Deps) http.Handler {
	a := &api{Deps: d}
	mux := http.NewServeMux()

	mux.HandleFunc("GET /healthz", a.healthz)
	mux.HandleFunc("GET /readyz", a.readyz)
	mux.HandleFunc("GET /version", a.version)

	mux.HandleFunc("POST /v1/auth/register", a.register)
	mux.HandleFunc("POST /v1/auth/login", a.login)
	protected := map[string]http.HandlerFunc{
		"GET /v1/me": a.me,

		"POST /v1/documents":               a.createDocument,
		"GET /v1/documents":                a.listDocuments,
		"GET /v1/documents/{id}":           a.getDocument,
		"PATCH /v1/documents/{id}":         a.renameDocument,
		"DELETE /v1/documents/{id}":        a.deleteDocument,
		"GET /v1/documents/{id}/content":   a.downloadDocument,
		"POST /v1/documents/{id}/versions": a.createVersion,
		"GET /v1/documents/{id}/versions":  a.listVersions,
		"GET /v1/documents/{id}/audit":     a.auditLog,

		"GET /v1/documents/{id}/permissions":               a.listPermissions,
		"PUT /v1/documents/{id}/permissions/{username}":    a.putPermission,
		"DELETE /v1/documents/{id}/permissions/{username}": a.deletePermission,
	}
	for pattern, h := range protected {
		mux.Handle(pattern, a.authenticated(h))
	}

	return requestID(securityHeaders(recoverer(d.Logger, accessLog(d.Logger, mux))))
}

func (a *api) healthz(w http.ResponseWriter, _ *http.Request) {
	a.writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (a *api) readyz(w http.ResponseWriter, r *http.Request) {
	checks := make(map[string]string, len(a.Readiness))
	status := http.StatusOK
	for name, check := range a.Readiness {
		if err := check(r.Context()); err != nil {
			a.Logger.WarnContext(r.Context(), "readiness check failed", "check", name, "err", err)
			checks[name] = "unavailable"
			status = http.StatusServiceUnavailable
			continue
		}
		checks[name] = "ok"
	}
	a.writeJSON(w, status, map[string]any{"checks": checks})
}

func (a *api) version(w http.ResponseWriter, _ *http.Request) {
	a.writeJSON(w, http.StatusOK, a.Build)
}
