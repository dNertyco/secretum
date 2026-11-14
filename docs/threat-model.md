# Threat model

This document states what Secretum protects, against whom, and — just as important — what it does not protect
against. It is updated together with the code.

## Assets

- Document contents and their derived data: extracted text, chunks, names, embeddings.
- Encryption keys: the master key (KEK) and per-document data keys (DEK).
- Metadata: who owns which document, permissions, audit log, search queries.

## Why application-level encryption

Disk encryption and encrypted backups (e.g. restic) protect data only while it is at rest on that disk or in that
backup repository. On a running server the database and files are readable by anyone who reaches them.
Application-level encryption keeps documents encrypted everywhere except inside the service at the moment of an
authorized request.

## Threats and mitigations

| # | Threat | Mitigation |
|---|---|---|
| T1 | Database dump, backup or disk snapshot leaks | Documents stored only as AES-256-GCM ciphertext; data keys wrapped by a master key kept outside the storage |
| T2 | Storage host or hosting provider is compromised | Same as T1: the attacker gets ciphertext and wrapped keys without the master key |
| T3 | Arbitrary file read in the service or a neighbouring app | Blobs on disk are ciphertext |
| T4 | Ciphertext tampering or swapping between documents | GCM authentication; document ID and version bound as additional authenticated data |
| T5 | Insider with database access | Separation of duties: database access does not grant key access |
| T6 | Document must be deleted irreversibly (personal data law) | Crypto-shredding: destroy the data key; embeddings and derived data are deleted too |
| T7 | Search reveals documents the user cannot access | Permission filter applied inside the vector query, not after it |
| T8 | Embeddings leak document contents | Embeddings treated as sensitive data, never exposed via API; chunks stored encrypted |
| T9 | Bulk exfiltration through the API or search | Rate limiting, audit log, alerts on unusual volume |
| T10 | Documents sent to third-party AI services | Embedding and naming models run locally |
| T11 | Prompt injection through document text (naming, future RAG) | Strict output format and length; models get no tools and only permitted chunks |

## Metadata stored in plaintext

To keep listing and access checks efficient, some metadata is not encrypted: document and user IDs, owner, version
numbers, sizes, detected content types, timestamps, permissions and the audit log. Document names and contents are
encrypted.

## Known limitations

- The local key manager keeps master keys in the service's memory (loaded from configuration). A production
  deployment should use an external KMS behind the same `KeyManager` interface.
- Whole files are encrypted in memory; the upload size limit (32 MiB by default) bounds memory use.
- Rate limits are per service instance.

## Out of scope

- **Full compromise of the running service.** The service decrypts documents to serve them, so an attacker
  controlling it can read what it can read. Mitigated only partially: master key outside the host, audit, rate limits.
- **Stolen user credentials.** An attacker with a valid token sees what that user sees. Mitigated by short-lived
  tokens and audit, not by encryption.
- Side-channel attacks and denial of service.

## Cryptography rules

- Only Go standard library primitives (`crypto/aes`, `crypto/cipher`, `crypto/rand`); no custom algorithms.
- AES-256-GCM with a random 96-bit nonce per encryption; a data key encrypts a bounded number of messages.
- Keys never appear in logs, errors, metrics or API responses.
