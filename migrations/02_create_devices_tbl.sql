-- +goose Up
-- +goose StatementBegin
SELECT 'up SQL query';

SET search_path = tesla_oracle, public;

CREATE TABLE devices
(
    synthetic_device_address BYTEA PRIMARY KEY
        CONSTRAINT synthetic_device_address_check CHECK (length(synthetic_device_address) = 20),
    vin text NOT NULL
        CONSTRAINT valid_vin_check CHECK (length(vin) = 17),
    wallet_child_number int NOT NULL UNIQUE,
    token_id int UNIQUE,
    synthetic_token_id int UNIQUE
); 

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
SELECT 'down SQL query';

SET search_path = tesla_oracle, public;

DROP TABLE devices;
-- +goose StatementEnd
