CREATE TABLE reports (
    id      serial PRIMARY KEY,
    title   text NOT NULL,
    "Owner" varchar(64)
);
