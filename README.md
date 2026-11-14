# Secretum

[![CI](https://github.com/dNertyco/secretum/actions/workflows/ci.yml/badge.svg)](https://github.com/dNertyco/secretum/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

Secure document storage with application-level encryption and AI-powered search.

Secretum stores sensitive documents (contracts, service reports, records with personal data) so that a leaked
database dump, backup or disk snapshot reveals nothing readable. Scanned documents get a meaningful name from their
content, and users can find them by meaning, never seeing documents they are not allowed to access.

> **Status:** early development. See the [roadmap](#roadmap).

## Features (planned)

- **Envelope encryption** — every document has its own data key (AES-256-GCM); data keys are wrapped by a master key
  kept outside the storage.
- **Access control and audit** — per-document permissions, audit log of every read, search and change.
- **Crypto-shredding** — deleting a document's key makes it unreadable everywhere, including old backups.
- **Automatic naming** — OCR and content analysis turn `scan_0042.pdf` into
  `Service report No. 123, 2026-02-01, Ventilator C3`.
- **Semantic search** — local embedding model, pgvector, permission filtering inside the query.

Why application-level encryption when disks and backups can already be encrypted — see the
[threat model](docs/threat-model.md).

## Architecture

```text
client ──► HTTP API (Go) ──► PostgreSQL   metadata, wrapped keys, permissions, audit, vectors
               │
               ├──────────► MinIO (S3)   encrypted document blobs
               │
               └──────────► Key manager  master key, never leaves it
```

## Quick start

Requirements: Go 1.27+, Docker with Compose.

```bash
cp .env.example .env
make up                       # app + PostgreSQL + MinIO
curl localhost:8080/healthz
```

Development:

```bash
make test    # unit tests with the race detector
make lint    # golangci-lint
make run     # run the service locally
make help    # all targets
```

## Configuration

| Variable | Default | Description |
|---|---|---|
| `SECRETUM_HTTP_ADDR` | `:8080` | HTTP listen address |
| `SECRETUM_LOG_LEVEL` | `info` | `debug`, `info`, `warn`, `error` |
| `SECRETUM_SHUTDOWN_TIMEOUT` | `10s` | Graceful shutdown timeout |

## Roadmap

- [x] Project skeleton: HTTP server, graceful shutdown, structured logs, CI
- [ ] Encrypted storage: upload, download, versions, envelope encryption
- [ ] Authentication, per-document permissions, audit log
- [ ] Processing pipeline: text extraction, OCR, automatic naming
- [ ] Semantic search with pgvector and permission filtering
- [ ] Metrics, tracing, load testing results
- [ ] gRPC API, master key rotation, encrypted off-site replication

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Security issues — [SECURITY.md](SECURITY.md).

## License

[MIT](LICENSE)
