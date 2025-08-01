-- +goose Up
-- +goose StatementBegin
ALTER TABLE synthetic_devices
    ADD COLUMN subscription_status TEXT
        CONSTRAINT subscription_status_check CHECK (subscription_status IN ('pending', 'active', 'inactive'))
        DEFAULT 'pending';
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE synthetic_devices
    DROP COLUMN subscription_status;
-- +goose StatementEnd
