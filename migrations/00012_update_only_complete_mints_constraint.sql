-- +goose Up
-- +goose StatementBegin
-- Update only_complete_mints constraint to allow disconnected state
-- Old: (vehicle_token_id IS NULL AND token_id IS NULL) OR (vehicle_token_id IS NOT NULL AND token_id IS NOT NULL)
-- New: Allow three valid states:
--   1. Not minted: both NULL (initial state before any minting)
--   2. Fully connected: both NOT NULL (vehicle and SD both minted and connected)
--   3. Disconnected: vehicle_token_id NOT NULL, token_id NULL (SD burned, vehicle preserved for reconnection)
--
-- Intentionally DISALLOWED state:
--   4. Invalid: vehicle_token_id IS NULL AND token_id IS NOT NULL
--      (Cannot have SD without Vehicle - violates business logic)
ALTER TABLE tesla_oracle.synthetic_devices
DROP CONSTRAINT only_complete_mints;

ALTER TABLE tesla_oracle.synthetic_devices
ADD CONSTRAINT only_complete_mints CHECK (
    (vehicle_token_id IS NULL AND token_id IS NULL)
    OR
    (vehicle_token_id IS NOT NULL AND token_id IS NOT NULL)
    OR
    (vehicle_token_id IS NOT NULL AND token_id IS NULL)
);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
-- Restore original constraint (doesn't allow disconnected state)
ALTER TABLE tesla_oracle.synthetic_devices
DROP CONSTRAINT only_complete_mints;

ALTER TABLE tesla_oracle.synthetic_devices
ADD CONSTRAINT only_complete_mints CHECK (
    (vehicle_token_id IS NULL AND token_id IS NULL)
    OR
    (vehicle_token_id IS NOT NULL AND token_id IS NOT NULL)
);
-- +goose StatementEnd
