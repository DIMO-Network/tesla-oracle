-- +goose Up
-- +goose StatementBegin
REVOKE CREATE ON schema public FROM public;
CREATE SCHEMA IF NOT EXISTS tesla_oracle;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP SCHEMA tesla_oracle CASCADE;
GRANT CREATE USAGE ON schema public TO public;
-- +goose StatementEnd
