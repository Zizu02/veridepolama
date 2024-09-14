const db = require('../config/database'); // Veritabanı bağlantısı

async function getUserInfoByEmail(email) {
    // Veritabanı sorgusu
    try {
        const result = await db.query('SELECT * FROM users WHERE email = $1', [email]);
        return result.rows[0]; // PostgreSQL kullanıyorsanız `rows` dizisinden ilk elemanı döndürün
    } catch (error) {
        console.error('Veritabanı hatası:', error);
        throw error;
    }
}

module.exports = {
    getUserInfoByEmail
};


