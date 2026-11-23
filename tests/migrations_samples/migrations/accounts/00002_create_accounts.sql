-- +goose Up
CREATE TABLE billing.accounts (
    id        uuid PRIMARY KEY,
    client_id bigint NOT NULL REFERENCES clients (id),
    balance   numeric(20, 2) NOT NULL DEFAULT 0,
    currency  char(3) NOT NULL,
    CONSTRAINT accounts_currency_check CHECK (currency <> '')
);
CREATE INDEX accounts_client_id_idx ON billing.accounts (client_id);

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION touch_updated_at() RETURNS trigger AS $$
BEGIN
    NEW.updated_at = now();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd

-- +goose Down
DROP TABLE billing.accounts;
