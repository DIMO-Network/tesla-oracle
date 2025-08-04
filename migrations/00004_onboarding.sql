-- +goose Up
-- +goose StatementBegin

CREATE TABLE onboarding
(
    vin                         VARCHAR(17)       NOT NULL
        CONSTRAINT vins_pk PRIMARY KEY,
    vehicle_token_id            BIGINT
        CONSTRAINT unique_vehicle_token_id UNIQUE,
    synthetic_token_id          BIGINT
        CONSTRAINT unique_synthetic_token_id UNIQUE,
    external_id                 VARCHAR(255),
    onboarding_status           INTEGER DEFAULT 0 NOT NULL,
    device_definition_id        TEXT,
    wallet_index                BIGINT
);

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

DROP TABLE onboarding;

-- +goose StatementEnd
