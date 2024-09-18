const pool = require('../db'); // Veritabanı bağlantısını çağırıyoruz

const ProductsModel = {
    getAllProducts: async () => {
        const result = await pool.query('SELECT * FROM products');
        return result.rows;
    },
    getProductByName: async (name) => {
        const result = await pool.query('SELECT * FROM products WHERE name = $1', [name]);
        return result.rows[0];
    }
};

module.exports = ProductsModel;
