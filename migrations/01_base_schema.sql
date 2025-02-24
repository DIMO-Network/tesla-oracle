-- +goose Up
-- +goose StatementBegin
SELECT 'up SQL query';
REVOKE CREATE ON schema public FROM public;
CREATE SCHEMA IF NOT EXISTS tesla_oracle;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
SELECT 'down SQL query';
DROP SCHEMA tesla_oracle CASCADE;
GRANT CREATE, USAGE ON schema public TO public;
-- +goose StatementEnd
