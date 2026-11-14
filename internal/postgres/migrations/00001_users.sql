-- +goose Up
CREATE TABLE users (
    id            uuid        PRIMARY KEY,
    username      text        NOT NULL,
    password_hash text        NOT NULL,
    created_at    timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT users_username_key UNIQUE (username)
);

-- +goose Down
DROP TABLE users;
