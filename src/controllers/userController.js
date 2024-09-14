const db = require('../config/database'); // Veritabanı bağlantısı

async function getUserInfoByEmail(email) {
    // Bu sadece örnek bir kod, veritabanı bağlantısı ve sorgusu gerçek uygulamanızda farklı olabilir
    return db.query('SELECT * FROM users WHERE email = ?', [email])
        .then(result => result[0])
        .catch(error => {
            console.error('Veritabanı hatası:', error);
            throw error;
        });
}

module.exports = {
    getUserInfoByEmail
};
