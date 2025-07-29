-- +goose Up
-- +goose StatementBegin
SELECT 'up SQL query';

create sequence sd_wallet_index_seq
    start with 1;

-- NOTE: Gap for initial value in case of new indexes created during migration
select setval('sd_wallet_index_seq', (select coalesce(max(onboarding.wallet_index), 0) + 100 from onboarding));
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
SELECT 'down SQL query';

drop sequence sd_wallet_index_seq;

-- +goose StatementEnd
