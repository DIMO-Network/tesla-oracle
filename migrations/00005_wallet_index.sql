-- +goose Up
-- +goose StatementBegin
SELECT 'up SQL query';

CREATE SEQUENCE sd_wallet_index_seq
    START WITH 1;

-- NOTE: Gap for initial value in case of new indexes created during migration
SELECT setval('sd_wallet_index_seq', (SELECT coalesce(max(onboarding.wallet_index), 0) + 100 FROM onboarding));
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
SELECT 'down SQL query';

DROP SEQUENCE sd_wallet_index_seq;

-- +goose StatementEnd
