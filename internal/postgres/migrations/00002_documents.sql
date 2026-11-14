-- +goose Up
CREATE TABLE documents (
    id               uuid        PRIMARY KEY,
    owner_id         uuid        NOT NULL REFERENCES users (id),
    -- Encrypted with the metadata key; NULL once the document is shredded.
    name_ciphertext  bytea,
    meta_wrapped_key bytea,
    meta_kek_id      text        NOT NULL,
    current_version  integer     NOT NULL CHECK (current_version > 0),
    created_at       timestamptz NOT NULL,
    updated_at       timestamptz NOT NULL,
    deleted_at       timestamptz
);

CREATE TABLE document_versions (
    document_id  uuid        NOT NULL REFERENCES documents (id) ON DELETE CASCADE,
    version      integer     NOT NULL CHECK (version > 0),
    blob_key     text        NOT NULL,
    -- The version's data key wrapped by the master key; NULL once shredded.
    wrapped_key  bytea,
    kek_id       text        NOT NULL,
    size         bigint      NOT NULL CHECK (size >= 0),
    content_type text        NOT NULL,
    created_by   uuid        NOT NULL REFERENCES users (id),
    created_at   timestamptz NOT NULL,
    PRIMARY KEY (document_id, version)
);

CREATE TABLE document_permissions (
    document_id uuid        NOT NULL REFERENCES documents (id) ON DELETE CASCADE,
    user_id     uuid        NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    role        text        NOT NULL CHECK (role IN ('viewer', 'editor', 'owner')),
    granted_by  uuid        NOT NULL REFERENCES users (id),
    granted_at  timestamptz NOT NULL,
    PRIMARY KEY (document_id, user_id)
);

-- Listing a user's documents walks this index newest first.
CREATE INDEX document_permissions_user_idx ON document_permissions (user_id, document_id DESC);

-- Append-only audit log. No foreign keys: events must outlive documents and
-- may reference documents that never existed (denied probes).
CREATE TABLE audit_events (
    id          bigint      GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    occurred_at timestamptz NOT NULL,
    actor_id    uuid,
    action      text        NOT NULL,
    document_id uuid,
    outcome     text        NOT NULL CHECK (outcome IN ('success', 'denied')),
    request_id  text        NOT NULL DEFAULT '',
    client_ip   text        NOT NULL DEFAULT ''
);

CREATE INDEX audit_events_document_idx ON audit_events (document_id, id DESC);

-- +goose Down
DROP TABLE audit_events;
DROP TABLE document_permissions;
DROP TABLE document_versions;
DROP TABLE documents;
