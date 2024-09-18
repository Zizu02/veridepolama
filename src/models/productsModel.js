const db = require('../../config/database');

const ProductsModel = {
    getAllProducts: async () => {
        const result = await db.query('SELECT * FROM products');
        return result.rows;
    },
    getProductByName: async (name) => {
        const result = await db.query('SELECT * FROM products WHERE name = $1', [name]);
        return result.rows[0];
    },
    // Ürün eklemek için fonksiyon
    addProduct: async (name, price) => {
        const result = await db.query('INSERT INTO products (name, price) VALUES ($1, $2) RETURNING *', [name, price]);
        return result.rows[0];
    },
    // Ürün güncellemek için fonksiyon
    updateProduct: async (id, name, price) => {
        const result = await db.query('UPDATE products SET name = $1, price = $2 WHERE id = $3 RETURNING *', [name, price, id]);
        return result.rows[0];
    },
    // Ürün silmek için fonksiyon
    deleteProduct: async (id) => {
        const result = await db.query('DELETE FROM products WHERE id = $1 RETURNING *', [id]);
        return result.rows[0];
    }
};

module.exports = ProductsModel;
