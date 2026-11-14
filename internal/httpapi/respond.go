package httpapi

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
)

const maxJSONBodyBytes = 1 << 20

type errorBody struct {
	Error errorDetail `json:"error"`
}

type errorDetail struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func (a *api) writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		a.Logger.Error("write response", "err", err)
	}
}

func (a *api) writeError(w http.ResponseWriter, status int, code, message string) {
	a.writeJSON(w, status, errorBody{Error: errorDetail{Code: code, Message: message}})
}

// internalError logs err and responds with a generic message so that
// internal details never leak to clients.
func (a *api) internalError(w http.ResponseWriter, r *http.Request, err error) {
	a.Logger.ErrorContext(r.Context(), "internal error",
		"err", err,
		"request_id", RequestIDFrom(r.Context()),
	)
	a.writeError(w, http.StatusInternalServerError, "internal", "internal server error")
}

// decodeJSON decodes a single JSON object from the request body into dst,
// rejecting unknown fields and oversized bodies.
func decodeJSON(w http.ResponseWriter, r *http.Request, dst any) error {
	r.Body = http.MaxBytesReader(w, r.Body, maxJSONBodyBytes)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return fmt.Errorf("invalid JSON body: %w", err)
	}
	if dec.More() {
		return errors.New("invalid JSON body: unexpected data after object")
	}
	return nil
}
