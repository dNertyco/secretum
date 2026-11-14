# Changelog

All notable changes to this project are documented in this file.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Envelope encryption (AES-256-GCM): per-version data keys, encrypted names, AAD binding to document and version,
  several master keys for rotation.
- Encrypted document storage in S3-compatible object storage (MinIO): upload, download, versions with optimistic
  locking, rename.
- Per-document roles (owner, editor, viewer), sharing by username, `404` for users without access.
- Audit log of downloads, changes, sharing and denied attempts; downloads fail closed if auditing fails.
- Crypto-shredding on delete.
- Security headers; downloads are always served as attachments in a sandbox.
- Repository contract tests shared by the in-memory and PostgreSQL implementations; MinIO in CI.
- User registration and login: Argon2id password hashing, constant-time verification, protection against username
  enumeration by timing.
- Short-lived HS256 access tokens (`Authorization: Bearer`), `GET /v1/me`.
- Per-IP rate limiting of login and registration.
- PostgreSQL connection pool, embedded schema migrations (goose), `GET /readyz`.
- HTTP server with `/healthz` and `/version`, request ID, access logging and panic recovery.
- Configuration from environment variables, graceful shutdown.
- Dockerfile, Docker Compose stack with PostgreSQL and MinIO, Makefile.
- CI: golangci-lint, tests with the race detector, Docker image build.
- Threat model, contributing guide, security policy.
