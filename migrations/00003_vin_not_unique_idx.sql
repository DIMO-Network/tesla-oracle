-- +goose Up
-- +goose StatementBegin
ALTER TABLE synthetic_devices
DROP CONSTRAINT synthetic_devices_vin_key;

CREATE INDEX vin_idx
    ON synthetic_devices(vin);

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

DROP INDEX vin_idx;

ALTER TABLE synthetic_devices
ADD CONSTRAINT synthetic_devices_vin_key UNIQUE (vin);
-- +goose StatementEnd
