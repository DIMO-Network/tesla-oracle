-- +goose Up
-- +goose StatementBegin
ALTER TABLE synthetic_devices
    ADD COLUMN access_token TEXT NOT NULL,
    ADD COLUMN access_expires_at TIMESTAMP NOT NULL,
    ADD COLUMN refresh_token TEXT NOT NULL,
    ADD COLUMN refresh_expires_at TIMESTAMP NOT NULL;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE synthetic_devices
    DROP COLUMN access_token,
    DROP COLUMN access_expires_at,
    DROP COLUMN refresh_token,
    DROP COLUMN refresh_expires_at;
-- +goose StatementEnd
