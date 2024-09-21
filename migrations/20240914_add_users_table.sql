-- migrations/20240914_add_users_table.sql
CREATE TABLE orders (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES "user"(id) ON DELETE CASCADE,
    items JSONB,
    total_amount DECIMAL(10, 2),
    status VARCHAR(50) DEFAULT 'onay bekliyor',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE products (
    id SERIAL PRIMARY KEY,
    name VARCHAR(255) UNIQUE NOT NULL,
    price DECIMAL(10, 2) NOT NULL
);

INSERT INTO products (name, price) VALUES
('Adana kebap', 00.00),
('Kuzu Tandır', 25.00),
('Mercimek Çorbası', 25.00),
('Arabaşı Çorbası', 25.00),
('Salata', 2.00),
('Mevsim Salata', 3.00),
('Baklava', 5.00),
('Trileçe', 4.00),
('Ayran', 1.00),
('Limonata', 2.00),
('Hamburger Menü', 13.00),
('Pizza Menü', 18.00);

ALTER TABLE orders ADD COLUMN table_number VARCHAR(255);

INSERT INTO orders (table_number) VALUES
('Masa 1'),
('Masa 2'),
('Masa 3'),
('Masa 4'),
('Masa 5'),
('Masa 6'),
('Masa 7'),
('Masa 8'),
('Masa 9'),
('Masa 10');
