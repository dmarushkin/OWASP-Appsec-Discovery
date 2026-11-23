-- +goose Up
CREATE TABLE payments (
    id         bigint NOT NULL,
    account_id uuid NOT NULL,
    amount     numeric(20,2) NOT NULL,
    card_pan   bigint array,
    created_at timestamptz NOT NULL
) PARTITION BY RANGE (created_at);

CREATE TABLE payments_2024 PARTITION OF payments FOR VALUES FROM ('2024-01-01') TO ('2025-01-01');
CREATE TABLE payments_2025 (LIKE payments INCLUDING ALL);
ALTER TABLE payments ATTACH PARTITION payments_2025 FOR VALUES FROM ('2025-01-01') TO ('2026-01-01');

CREATE TABLE import_buffer (id int, payload jsonb);
ALTER TABLE import_buffer RENAME TO payment_imports;
CREATE TABLE legacy_transfers (id int);
DROP TABLE IF EXISTS legacy_transfers, legacy_fees CASCADE;
ALTER TABLE clients FROBNICATE EVERYTHING;
INSERT INTO clients (name) VALUES ('seed; not a statement end');

-- +goose Down
DROP TABLE payments;
