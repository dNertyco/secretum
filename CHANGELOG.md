# Changelog

All notable changes to this project are documented in this file.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

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
