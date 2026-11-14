package config

import (
	"log/slog"
	"testing"
	"time"
)

func lookupFrom(env map[string]string) lookupFunc {
	return func(key string) (string, bool) {
		v, ok := env[key]
		return v, ok
	}
}

func TestLoadDefaults(t *testing.T) {
	cfg, err := load(lookupFrom(nil))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg.HTTPAddr != ":8080" {
		t.Errorf("HTTPAddr = %q, want %q", cfg.HTTPAddr, ":8080")
	}
	if cfg.LogLevel != slog.LevelInfo {
		t.Errorf("LogLevel = %v, want %v", cfg.LogLevel, slog.LevelInfo)
	}
	if cfg.ShutdownTimeout != 10*time.Second {
		t.Errorf("ShutdownTimeout = %v, want %v", cfg.ShutdownTimeout, 10*time.Second)
	}
}

func TestLoadOverrides(t *testing.T) {
	cfg, err := load(lookupFrom(map[string]string{
		"SECRETUM_HTTP_ADDR":        "127.0.0.1:9000",
		"SECRETUM_LOG_LEVEL":        "debug",
		"SECRETUM_SHUTDOWN_TIMEOUT": "3s",
	}))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg.HTTPAddr != "127.0.0.1:9000" {
		t.Errorf("HTTPAddr = %q", cfg.HTTPAddr)
	}
	if cfg.LogLevel != slog.LevelDebug {
		t.Errorf("LogLevel = %v", cfg.LogLevel)
	}
	if cfg.ShutdownTimeout != 3*time.Second {
		t.Errorf("ShutdownTimeout = %v", cfg.ShutdownTimeout)
	}
}

func TestLoadInvalid(t *testing.T) {
	tests := map[string]map[string]string{
		"bad log level":        {"SECRETUM_LOG_LEVEL": "loud"},
		"bad timeout":          {"SECRETUM_SHUTDOWN_TIMEOUT": "soon"},
		"non-positive timeout": {"SECRETUM_SHUTDOWN_TIMEOUT": "0s"},
	}
	for name, env := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := load(lookupFrom(env)); err == nil {
				t.Fatal("expected error, got nil")
			}
		})
	}
}
