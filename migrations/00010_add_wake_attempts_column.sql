-- +goose Up
-- +goose StatementBegin
ALTER TABLE device_command_requests 
ADD COLUMN wake_attempts INTEGER NOT NULL DEFAULT 0;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE device_command_requests 
DROP COLUMN IF EXISTS wake_attempts;
-- +goose StatementEnd