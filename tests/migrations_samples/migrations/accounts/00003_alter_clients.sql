-- +goose Up
ALTER TABLE clients ADD COLUMN IF NOT EXISTS phone varchar(20), ADD COLUMN passport_number text;
ALTER TABLE clients RENAME COLUMN full_name TO name;
ALTER TABLE clients ALTER COLUMN email TYPE varchar(320);
ALTER TABLE clients ADD CONSTRAINT clients_email_key UNIQUE (email);
COMMENT ON TABLE clients IS 'Bank clients';
COMMENT ON COLUMN clients.passport_number IS 'Identity document number';

-- +goose Down
ALTER TABLE clients DROP COLUMN phone;
