-- +goose Up
-- +goose StatementBegin
ALTER TABLE tesla_oracle.synthetic_devices
ALTER COLUMN wallet_child_number DROP NOT NULL;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
-- Before adding NOT NULL constraint back, set NULL values to 0
UPDATE tesla_oracle.synthetic_devices
SET wallet_child_number = 0
WHERE wallet_child_number IS NULL;

ALTER TABLE tesla_oracle.synthetic_devices
ALTER COLUMN wallet_child_number SET NOT NULL;
-- +goose StatementEnd
