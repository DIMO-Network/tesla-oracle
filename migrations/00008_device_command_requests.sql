-- +goose Up
-- +goose StatementBegin
CREATE TABLE device_command_requests (
    id VARCHAR PRIMARY KEY,              -- taskID (KSUID)
    vehicle_token_id INTEGER NOT NULL,   -- Vehicle token ID from synthetic device
    command VARCHAR NOT NULL,           -- Command type: "frunk/open", "doors/lock", etc.
    status VARCHAR NOT NULL DEFAULT 'pending', -- "pending", "completed", "failed"
    error_message TEXT,                 -- Error details if status is "failed"
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP NOT NULL DEFAULT NOW(),
    CONSTRAINT fk_vehicle_token_id FOREIGN KEY (vehicle_token_id) REFERENCES synthetic_devices (vehicle_token_id)
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
