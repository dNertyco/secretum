// Package httpapi implements the HTTP transport layer of the service.
package httpapi

import (
	"context"
	"log/slog"
	"net/http"

	"github.com/dNertyco/secretum/internal/auth"
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
	mux.Handle("GET /v1/me", a.authenticated(http.HandlerFunc(a.me)))

	return requestID(recoverer(d.Logger, accessLog(d.Logger, mux)))
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
