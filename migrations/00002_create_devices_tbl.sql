-- +goose Up
-- +goose StatementBegin
CREATE TABLE synthetic_devices
(
    address BYTEA PRIMARY KEY
        CONSTRAINT synthetic_device_address_check CHECK (length(address) = 20),
    vin text NOT NULL UNIQUE
        CONSTRAINT valid_vin_check CHECK (length(vin) = 17),
    wallet_child_number int NOT NULL UNIQUE CHECK(wallet_child_number > 0),
    vehicle_token_id int UNIQUE,
    token_id int UNIQUE
        CONSTRAINT only_complete_mints CHECK (
            (vehicle_token_id IS NULL AND token_id IS NULL) 
            OR 
            (vehicle_token_id IS NOT NULL AND token_id IS NOT NULL) 
            )
); 

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE synthetic_devices;
-- +goose StatementEnd
