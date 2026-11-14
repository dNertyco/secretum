// Package config loads service configuration from environment variables.
package config

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"time"
)

// minJWTSecretLen is the minimum length of the token signing secret (256 bits).
const minJWTSecretLen = 32

// Config holds runtime settings of the service.
type Config struct {
	HTTPAddr        string
	LogLevel        slog.Level
	ShutdownTimeout time.Duration

	DatabaseURL    string
	MigrateOnStart bool

	JWTSecret         []byte
	TokenTTL          time.Duration
	AllowRegistration bool

	// LoginRatePerMinute limits login attempts per client IP.
	LoginRatePerMinute int
}

// Load reads configuration from environment variables, applying defaults
// for unset values.
func Load() (Config, error) {
	return load(os.LookupEnv)
}

type lookupFunc func(key string) (string, bool)

type parser struct {
	lookup lookupFunc
	errs   []error
}

func (p *parser) get(key string) (string, bool) {
	v, ok := p.lookup(key)
	return v, ok && v != ""
}

func (p *parser) str(key string, dst *string) {
	if v, ok := p.get(key); ok {
		*dst = v
	}
}

func (p *parser) duration(key string, dst *time.Duration) {
	v, ok := p.get(key)
	if !ok {
		return
	}
	d, err := time.ParseDuration(v)
	switch {
	case err != nil:
		p.errs = append(p.errs, fmt.Errorf("%s: %w", key, err))
	case d <= 0:
		p.errs = append(p.errs, fmt.Errorf("%s: must be positive, got %s", key, d))
	default:
		*dst = d
	}
}

func (p *parser) boolean(key string, dst *bool) {
	v, ok := p.get(key)
	if !ok {
		return
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		p.errs = append(p.errs, fmt.Errorf("%s: %w", key, err))
		return
	}
	*dst = b
}

func (p *parser) positiveInt(key string, dst *int) {
	v, ok := p.get(key)
	if !ok {
		return
	}
	n, err := strconv.Atoi(v)
	if err != nil || n <= 0 {
		p.errs = append(p.errs, fmt.Errorf("%s: must be a positive integer, got %q", key, v))
		return
	}
	*dst = n
}

func load(lookup lookupFunc) (Config, error) {
	cfg := Config{
		HTTPAddr:           ":8080",
		LogLevel:           slog.LevelInfo,
		ShutdownTimeout:    10 * time.Second,
		MigrateOnStart:     true,
		TokenTTL:           15 * time.Minute,
		AllowRegistration:  true,
		LoginRatePerMinute: 10,
	}
	p := &parser{lookup: lookup}

	p.str("SECRETUM_HTTP_ADDR", &cfg.HTTPAddr)
	if v, ok := p.get("SECRETUM_LOG_LEVEL"); ok {
		if err := cfg.LogLevel.UnmarshalText([]byte(v)); err != nil {
			p.errs = append(p.errs, fmt.Errorf("SECRETUM_LOG_LEVEL: %w", err))
		}
	}
	p.duration("SECRETUM_SHUTDOWN_TIMEOUT", &cfg.ShutdownTimeout)

	p.str("SECRETUM_DATABASE_URL", &cfg.DatabaseURL)
	p.boolean("SECRETUM_MIGRATE_ON_START", &cfg.MigrateOnStart)

	var secret string
	p.str("SECRETUM_JWT_SECRET", &secret)
	cfg.JWTSecret = []byte(secret)
	p.duration("SECRETUM_TOKEN_TTL", &cfg.TokenTTL)
	p.boolean("SECRETUM_ALLOW_REGISTRATION", &cfg.AllowRegistration)
	p.positiveInt("SECRETUM_LOGIN_RATE_PER_MINUTE", &cfg.LoginRatePerMinute)

	if cfg.DatabaseURL == "" {
		p.errs = append(p.errs, errors.New("SECRETUM_DATABASE_URL: required"))
	}
	if len(cfg.JWTSecret) < minJWTSecretLen {
		p.errs = append(p.errs, fmt.Errorf("SECRETUM_JWT_SECRET: must be at least %d bytes", minJWTSecretLen))
	}

	if err := errors.Join(p.errs...); err != nil {
		return Config{}, err
	}
	return cfg, nil
}
