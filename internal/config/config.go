// Package config loads service configuration from environment variables.
package config

import (
	"fmt"
	"log/slog"
	"os"
	"time"
)

// Config holds runtime settings of the service.
type Config struct {
	HTTPAddr        string
	LogLevel        slog.Level
	ShutdownTimeout time.Duration
}

// Load reads configuration from environment variables, applying defaults
// for unset values.
func Load() (Config, error) {
	return load(os.LookupEnv)
}

type lookupFunc func(key string) (string, bool)

func load(lookup lookupFunc) (Config, error) {
	cfg := Config{
		HTTPAddr:        ":8080",
		LogLevel:        slog.LevelInfo,
		ShutdownTimeout: 10 * time.Second,
	}

	if v, ok := lookup("SECRETUM_HTTP_ADDR"); ok && v != "" {
		cfg.HTTPAddr = v
	}

	if v, ok := lookup("SECRETUM_LOG_LEVEL"); ok && v != "" {
		if err := cfg.LogLevel.UnmarshalText([]byte(v)); err != nil {
			return Config{}, fmt.Errorf("SECRETUM_LOG_LEVEL: %w", err)
		}
	}

	if v, ok := lookup("SECRETUM_SHUTDOWN_TIMEOUT"); ok && v != "" {
		d, err := time.ParseDuration(v)
		if err != nil {
			return Config{}, fmt.Errorf("SECRETUM_SHUTDOWN_TIMEOUT: %w", err)
		}
		if d <= 0 {
			return Config{}, fmt.Errorf("SECRETUM_SHUTDOWN_TIMEOUT: must be positive, got %s", d)
		}
		cfg.ShutdownTimeout = d
	}

	return cfg, nil
}
