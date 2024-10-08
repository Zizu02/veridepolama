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

CREATE TABLE table_orders (
    id SERIAL PRIMARY KEY,
    table_number VARCHAR(255) NOT NULL,  -- Masanın numarası
    items JSONB NOT NULL,                -- Sipariş edilen ürünler
    total_amount DECIMAL(10, 2) NOT NULL, -- Toplam tutar
    status VARCHAR(50) DEFAULT 'onay bekliyor', -- Sipariş durumu
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP -- Sipariş oluşturulma zamanı
);
