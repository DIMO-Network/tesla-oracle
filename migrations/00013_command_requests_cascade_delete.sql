-- +goose Up
-- +goose StatementBegin
-- Command history belongs to the device row it points at. Without a delete rule,
-- deleting the synthetic device of any car that was ever sent a command (vehicle
-- burned) failed on this foreign key, every time.
ALTER TABLE tesla_oracle.device_command_requests
DROP CONSTRAINT fk_vehicle_token_id;

ALTER TABLE tesla_oracle.device_command_requests
ADD CONSTRAINT fk_vehicle_token_id FOREIGN KEY (vehicle_token_id)
    REFERENCES tesla_oracle.synthetic_devices (vehicle_token_id) ON DELETE CASCADE;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE tesla_oracle.device_command_requests
DROP CONSTRAINT fk_vehicle_token_id;

ALTER TABLE tesla_oracle.device_command_requests
ADD CONSTRAINT fk_vehicle_token_id FOREIGN KEY (vehicle_token_id)
    REFERENCES tesla_oracle.synthetic_devices (vehicle_token_id);
-- +goose StatementEnd
