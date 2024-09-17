-- migrations/20240914_add_users_table.sql
CREATE TABLE orders (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES "user"(id),
    items TEXT,
    total_amount DECIMAL(10, 2),
    status VARCHAR(50) DEFAULT 'onay bekliyor',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
