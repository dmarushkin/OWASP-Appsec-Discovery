-- +goose Up
-- +goose StatementBegin
CREATE TABLE IF NOT EXISTS clients (
    id         bigserial PRIMARY KEY,
    full_name  varchar(255) NOT NULL,
    email      text,
    created_at timestamp with time zone NOT NULL DEFAULT now()
);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE clients;
-- +goose StatementEnd
