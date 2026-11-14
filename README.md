# Secretum

[![CI](https://github.com/dNertyco/secretum/actions/workflows/ci.yml/badge.svg)](https://github.com/dNertyco/secretum/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

Secure document storage with application-level encryption and AI-powered search.

Secretum stores sensitive documents (contracts, service reports, records with personal data) so that a leaked
database dump, backup or disk snapshot reveals nothing readable. Scanned documents get a meaningful name from their
content, and users can find them by meaning, never seeing documents they are not allowed to access.

> **Status:** MVP — encrypted storage, access control and audit work; automatic naming and search are next.
> See the [roadmap](#roadmap).

## Features

- **Envelope encryption** — every document version has its own data key (AES-256-GCM); data keys are wrapped by a
  master key. Names are encrypted too. Additional authenticated data binds each ciphertext to its document and
  version, so swapped or tampered blobs fail to decrypt.
- **Master key rotation** — several master keys can be configured; new data keys use the active one, old ones stay
  readable. Documents are never re-encrypted, only data keys are re-wrapped.
- **Access control** — owner / editor / viewer roles per document; users without access get `404`, so document
  existence is not revealed.
- **Audit log** — downloads, changes, sharing and denied attempts with actor, request ID and client IP; a download
  fails if its audit record cannot be written.
- **Crypto-shredding** — deleting a document destroys its keys, making it unreadable everywhere, including backups.
- **Versions** — every upload of new content is a new version; concurrent uploads are resolved with optimistic locking.
- **Authentication** — Argon2id passwords, short-lived bearer tokens, per-IP rate limiting of login.

Planned:

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
# put real secrets into .env:
#   SECRETUM_JWT_SECRET=$(openssl rand -base64 48)
#   SECRETUM_MASTER_KEYS=k1:$(openssl rand -base64 32)
make up                       # app + PostgreSQL + MinIO
curl localhost:8080/readyz
```

Try it:

```bash
API=localhost:8080/v1
curl -s $API/auth/register -d '{"username":"alice","password":"correct-horse-battery"}'
TOKEN=$(curl -s $API/auth/login -d '{"username":"alice","password":"correct-horse-battery"}' | jq -r .access_token)

curl -s $API/documents -H "Authorization: Bearer $TOKEN" -F name="Service report 123" -F file=@report.pdf
curl -s $API/documents -H "Authorization: Bearer $TOKEN"
curl -s $API/documents/<id>/content -H "Authorization: Bearer $TOKEN" -o report.pdf
```

## API

All endpoints except health checks and authentication require `Authorization: Bearer <token>`.
Errors have the form `{"error": {"code": "...", "message": "..."}}`.

| Method | Path | Access | Description |
|---|---|---|---|
| `POST` | `/v1/auth/register` | — | Create an account |
| `POST` | `/v1/auth/login` | — | Get an access token |
| `GET` | `/v1/me` | any | Current user |
| `POST` | `/v1/documents` | any | Upload (`multipart/form-data`: `file`, optional `name`) |
| `GET` | `/v1/documents?limit=&after=` | any | Documents you can access, newest first |
| `GET` | `/v1/documents/{id}` | viewer | Metadata |
| `PATCH` | `/v1/documents/{id}` | editor | Rename (`{"name": "..."}`) |
| `DELETE` | `/v1/documents/{id}` | owner | Crypto-shred |
| `GET` | `/v1/documents/{id}/content?version=` | viewer | Download (current version by default) |
| `POST` | `/v1/documents/{id}/versions` | editor | Upload a new version |
| `GET` | `/v1/documents/{id}/versions` | viewer | Version history |
| `GET` | `/v1/documents/{id}/permissions` | owner | Who has access |
| `PUT` | `/v1/documents/{id}/permissions/{username}` | owner | Grant `viewer` or `editor` (`{"role": "..."}`) |
| `DELETE` | `/v1/documents/{id}/permissions/{username}` | owner | Revoke access |
| `GET` | `/v1/documents/{id}/audit` | owner | Latest audit events |
| `GET` | `/healthz`, `/readyz`, `/version` | — | Liveness, readiness, build info |

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
| `SECRETUM_DATABASE_URL` | — | PostgreSQL connection URL (required) |
| `SECRETUM_MIGRATE_ON_START` | `true` | Apply schema migrations on start |
| `SECRETUM_JWT_SECRET` | — | Token signing secret, at least 32 bytes (required) |
| `SECRETUM_TOKEN_TTL` | `15m` | Access token lifetime |
| `SECRETUM_ALLOW_REGISTRATION` | `true` | Allow self-registration |
| `SECRETUM_LOGIN_RATE_PER_MINUTE` | `10` | Login and registration attempts per client IP |
| `SECRETUM_MASTER_KEYS` | — | `id:base64key,...`, 32-byte keys (required) |
| `SECRETUM_ACTIVE_KEY_ID` | the only key | Master key for new data keys |
| `SECRETUM_MAX_UPLOAD_BYTES` | `33554432` | Maximum file size (32 MiB) |
| `SECRETUM_S3_ENDPOINT` | — | S3-compatible endpoint, e.g. `minio:9000` (required) |
| `SECRETUM_S3_ACCESS_KEY`, `SECRETUM_S3_SECRET_KEY` | — | Object storage credentials |
| `SECRETUM_S3_BUCKET` | `secretum` | Bucket, created if missing |
| `SECRETUM_S3_USE_SSL` | `false` | Use HTTPS for object storage |

## Roadmap

- [x] Project skeleton: HTTP server, graceful shutdown, structured logs, CI
- [x] Encrypted storage: upload, download, versions, envelope encryption
- [x] Authentication, per-document permissions, audit log
- [ ] Processing pipeline: text extraction, OCR, automatic naming
- [ ] Semantic search with pgvector and permission filtering
- [ ] Metrics, tracing, load testing results
- [ ] gRPC API, re-wrap command for master key rotation, external KMS, encrypted off-site replication
- [ ] Streaming encryption for large files, refresh tokens, Redis-backed rate limiting

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Security issues — [SECURITY.md](SECURITY.md).

## License

[MIT](LICENSE)
