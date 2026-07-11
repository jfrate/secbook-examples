-- Run these commands in psql to set up the base project database.
-- psql -U postgres
-- Then paste or \i this file.

CREATE DATABASE mysecuritydb;
\c mysecuritydb

CREATE TABLE users (
  id SERIAL PRIMARY KEY,
  name TEXT NOT NULL,
  favorite_ice_cream TEXT NOT NULL
);

INSERT INTO users (name, favorite_ice_cream) VALUES
  ('Alice', 'Vanilla'),
  ('Bob', 'Chocolate'),
  ('Carol', 'Strawberry'),
  ('Dan', 'Peach');
