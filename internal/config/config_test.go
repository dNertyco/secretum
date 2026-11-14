package config

import (
	"log/slog"
	"maps"
	"testing"
	"time"
)

func lookupFrom(env map[string]string) lookupFunc {
	return func(key string) (string, bool) {
		v, ok := env[key]
		return v, ok
	}
}

func requiredEnv() map[string]string {
	return map[string]string{
		"SECRETUM_DATABASE_URL": "postgres://localhost/secretum",
		"SECRETUM_JWT_SECRET":   "0123456789abcdef0123456789abcdef",
	}
}

func TestLoadDefaults(t *testing.T) {
	cfg, err := load(lookupFrom(requiredEnv()))
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
		t.Errorf("ShutdownTimeout = %v", cfg.ShutdownTimeout)
	}
	if !cfg.MigrateOnStart || !cfg.AllowRegistration {
		t.Errorf("MigrateOnStart = %v, AllowRegistration = %v, want true", cfg.MigrateOnStart, cfg.AllowRegistration)
	}
	if cfg.TokenTTL != 15*time.Minute {
		t.Errorf("TokenTTL = %v", cfg.TokenTTL)
	}
	if cfg.LoginRatePerMinute != 10 {
		t.Errorf("LoginRatePerMinute = %d", cfg.LoginRatePerMinute)
	}
}

func TestLoadOverrides(t *testing.T) {
	env := requiredEnv()
	maps.Copy(env, map[string]string{
		"SECRETUM_HTTP_ADDR":             "127.0.0.1:9000",
		"SECRETUM_LOG_LEVEL":             "debug",
		"SECRETUM_SHUTDOWN_TIMEOUT":      "3s",
		"SECRETUM_MIGRATE_ON_START":      "false",
		"SECRETUM_TOKEN_TTL":             "5m",
		"SECRETUM_ALLOW_REGISTRATION":    "false",
		"SECRETUM_LOGIN_RATE_PER_MINUTE": "3",
	})
	cfg, err := load(lookupFrom(env))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg.HTTPAddr != "127.0.0.1:9000" || cfg.LogLevel != slog.LevelDebug || cfg.ShutdownTimeout != 3*time.Second {
		t.Errorf("unexpected server settings: %+v", cfg)
	}
	if cfg.MigrateOnStart || cfg.AllowRegistration {
		t.Errorf("boolean overrides not applied: %+v", cfg)
	}
	if cfg.TokenTTL != 5*time.Minute || cfg.LoginRatePerMinute != 3 {
		t.Errorf("auth overrides not applied: %+v", cfg)
	}
}

func TestLoadInvalid(t *testing.T) {
	tests := map[string]map[string]string{
		"bad log level":        {"SECRETUM_LOG_LEVEL": "loud"},
		"bad timeout":          {"SECRETUM_SHUTDOWN_TIMEOUT": "soon"},
		"non-positive timeout": {"SECRETUM_SHUTDOWN_TIMEOUT": "0s"},
		"bad bool":             {"SECRETUM_MIGRATE_ON_START": "maybe"},
		"bad rate":             {"SECRETUM_LOGIN_RATE_PER_MINUTE": "-1"},
		"short jwt secret":     {"SECRETUM_JWT_SECRET": "short"},
		"missing database url": {"SECRETUM_DATABASE_URL": ""},
	}
	for name, override := range tests {
		t.Run(name, func(t *testing.T) {
			env := requiredEnv()
			maps.Copy(env, override)
			if _, err := load(lookupFrom(env)); err == nil {
				t.Fatal("expected error, got nil")
			}
		})
	}
}
