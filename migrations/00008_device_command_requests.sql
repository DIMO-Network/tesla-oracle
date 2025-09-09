-- +goose Up
-- +goose StatementBegin
CREATE TABLE device_command_requests (
    id VARCHAR PRIMARY KEY,              -- taskID (KSUID)
    vehicle_token_id INTEGER NOT NULL,   -- Vehicle token ID from synthetic device
    vin VARCHAR(17) NOT NULL,           -- Vehicle VIN
    command VARCHAR NOT NULL,           -- Command type: "frunk/open", "doors/lock", etc.
    event_type VARCHAR NOT NULL,        -- CloudEvent type: "zone.dimo.task.tesla.frunk.open"
    status VARCHAR NOT NULL DEFAULT 'pending', -- "pending", "completed", "failed"
    error_message TEXT,                 -- Error details if status is "failed"
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP NOT NULL DEFAULT NOW()
);

-- Indexes for efficient queries
CREATE INDEX idx_device_command_requests_vehicle_token_id ON device_command_requests(vehicle_token_id);
CREATE INDEX idx_device_command_requests_status ON device_command_requests(status);
CREATE INDEX idx_device_command_requests_created_at ON device_command_requests(created_at);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS device_command_requests;
-- +goose StatementEnd
