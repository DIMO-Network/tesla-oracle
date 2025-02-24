-- +goose Up
-- +goose StatementBegin
SELECT 'up SQL query';

SET search_path = tesla_oracle, public;

CREATE TABLE devices
(
    vin CHAR(17),
    synthetic_device_address BYTEA
        CONSTRAINT synthetic_device_address_check CHECK (length(synthetic_device_address) = 20),
    wallet_child_num numeric(78, 0) UNIQUE NOT NULL,
    token_id numeric(78, 0) UNIQUE NOT NULL,
    synthetic_token_id numeric(78,0) UNIQUE NOT NULL,
    CONSTRAINT full_device_pkey PRIMARY KEY (vin, synthetic_device_address)
); 

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
SELECT 'down SQL query';

SET search_path = tesla_oracle, public;

DROP TABLE devices;
-- +goose StatementEnd
