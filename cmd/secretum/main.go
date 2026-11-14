// Command secretum runs the Secretum document storage service.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/dNertyco/secretum/internal/auth"
	"github.com/dNertyco/secretum/internal/blob"
	"github.com/dNertyco/secretum/internal/config"
	"github.com/dNertyco/secretum/internal/documents"
	"github.com/dNertyco/secretum/internal/envelope"
	"github.com/dNertyco/secretum/internal/httpapi"
	"github.com/dNertyco/secretum/internal/postgres"
	"github.com/dNertyco/secretum/internal/ratelimit"
)

// Set at build time via -ldflags.
var (
	version = "dev"
	commit  = "none"
)

func main() {
	if err := run(); err != nil {
		slog.Error("service stopped with error", "err", err)
		os.Exit(1)
	}
}

func run() error {
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: cfg.LogLevel}))
	slog.SetDefault(logger)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	connectCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	pool, err := postgres.Connect(connectCtx, cfg.DatabaseURL)
	if err != nil {
		return fmt.Errorf("connect to database: %w", err)
	}
	defer pool.Close()

	if cfg.MigrateOnStart {
		if err := postgres.Migrate(connectCtx, pool); err != nil {
			return err
		}
		logger.Info("database migrations applied")
	}

	blobs, err := blob.NewS3(connectCtx, blob.S3Config{
		Endpoint:  cfg.S3Endpoint,
		AccessKey: cfg.S3AccessKey,
		SecretKey: cfg.S3SecretKey,
		Bucket:    cfg.S3Bucket,
		UseSSL:    cfg.S3UseSSL,
	})
	if err != nil {
		return fmt.Errorf("connect to object storage: %w", err)
	}

	keys, err := envelope.NewLocalKeyManager(cfg.MasterKeys, cfg.ActiveKeyID)
	if err != nil {
		return fmt.Errorf("init key manager: %w", err)
	}

	users := postgres.NewUsers(pool)
	authSvc, err := auth.NewService(users, auth.NewTokenIssuer(cfg.JWTSecret, cfg.TokenTTL))
	if err != nil {
		return fmt.Errorf("init auth: %w", err)
	}
	docSvc := documents.NewService(postgres.NewDocuments(pool), blobs, keys, users, logger)

	handler := httpapi.NewRouter(httpapi.Deps{
		Logger:            logger,
		Build:             httpapi.BuildInfo{Version: version, Commit: commit},
		Auth:              authSvc,
		Documents:         docSvc,
		MaxUploadBytes:    cfg.MaxUploadBytes,
		LoginLimiter:      ratelimit.New(cfg.LoginRatePerMinute, cfg.LoginRatePerMinute),
		AllowRegistration: cfg.AllowRegistration,
		Readiness: map[string]httpapi.ReadinessCheck{
			"postgres": func(ctx context.Context) error { return pool.Ping(ctx) },
			"storage":  blobs.Ping,
		},
	})

	srv := &http.Server{
		Addr:              cfg.HTTPAddr,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       60 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	errCh := make(chan error, 1)
	go func() {
		logger.Info("http server started", "addr", cfg.HTTPAddr, "version", version, "active_kek", keys.ActiveKEKID())
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
		close(errCh)
	}()

	select {
	case err := <-errCh:
		return fmt.Errorf("http server: %w", err)
	case <-ctx.Done():
	}

	logger.Info("shutting down", "timeout", cfg.ShutdownTimeout.String())
	shutdownCtx, cancel := context.WithTimeout(context.Background(), cfg.ShutdownTimeout)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		return fmt.Errorf("graceful shutdown: %w", err)
	}
	logger.Info("shutdown complete")
	return nil
}
