-- +goose Up
-- +goose StatementBegin
SELECT 'up SQL query';

SET search_path = tesla_oracle, public;

CREATE TABLE partial_devices
(
    vin CHAR(17) PRIMARY KEY,
    synthetic_device_address BYTEA
        CONSTRAINT synthetic_device_address_check CHECK (length(synthetic_device_address) = 20),
    wallet_child_num numeric(78, 0) UNIQUE NOT NULL
);

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
SELECT 'down SQL query';

SET search_path = tesla_oracle, public;

DROP TABLE partial_devices;
-- +goose StatementEnd
