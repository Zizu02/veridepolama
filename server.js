const express = require('express');
const app = express();
app.use(express.json());

// Veritabanına bağlantı (örneğin, MongoDB, PostgreSQL vs.)
const db = require('./config/database');

// Kullanıcı oluşturma endpoint'i
app.post('/create_account', async (req, res) => {
    const { email, password, address, phone } = req.body;

    try {
        // Veritabanına kullanıcı eklenir
        await db.query('INSERT INTO users (email, password, address, phone) VALUES (?, ?, ?, ?)', [email, password, address, phone]);
        res.json({ success: true, message: 'Hesap başarıyla oluşturuldu!' });
    } catch (error) {
        console.error('Veritabanı hatası:', error);
        res.status(500).json({ success: false, message: 'Veritabanı hatası', error });
    }
});

// Sunucu başlatma
app.listen(3000, () => {
    console.log('Sunucu 3000 portunda çalışıyor');
});
