// Package httpapi implements the HTTP transport layer of the service.
package httpapi

import (
	"encoding/json"
	"log/slog"
	"net/http"
)

// BuildInfo describes the running binary.
type BuildInfo struct {
	Version string `json:"version"`
	Commit  string `json:"commit"`
}

// NewRouter returns the root HTTP handler with all routes and middleware.
func NewRouter(logger *slog.Logger, build BuildInfo) http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, logger, http.StatusOK, map[string]string{"status": "ok"})
	})
	mux.HandleFunc("GET /version", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, logger, http.StatusOK, build)
	})

	return requestID(recoverer(logger, accessLog(logger, mux)))
}

func writeJSON(w http.ResponseWriter, logger *slog.Logger, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		logger.Error("write response", "err", err)
	}
}
