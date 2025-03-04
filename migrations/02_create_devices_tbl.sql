-- +goose Up
-- +goose StatementBegin
SELECT 'up SQL query';

SET search_path = tesla_oracle, public;
CREATE TABLE synthetic_devices
(
    device_address BYTEA PRIMARY KEY
        CONSTRAINT synthetic_device_address_check CHECK (length(device_address) = 20),
    vin text NOT NULL UNIQUE
        CONSTRAINT valid_vin_check CHECK (length(vin) = 17),
    wallet_child_number int NOT NULL UNIQUE CHECK(wallet_child_number > 0),
    vehicle_token_id int UNIQUE,
    synthetic_token_id int UNIQUE
        CONSTRAINT only_complete_mints CHECK (
            (vehicle_token_id IS NULL AND synthetic_token_id IS NULL) 
            OR 
            (vehicle_token_id IS NOT NULL AND synthetic_token_id IS NOT NULL) 
            )
); 

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
SELECT 'down SQL query';

SET search_path = tesla_oracle, public;

DROP TABLE synthetic_devices;
-- +goose StatementEnd
