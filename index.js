const express = require('express');
const app = express();
app.use(express.json());

// Veritabanına bağlantı
// const db = require('./config/database');

// Kullanıcı oluşturma endpoint'i
app.post('/create_account', (req, res) => {
    const { email, password, address, phone } = req.body;

    // Kullanıcı veritabanına eklenir
    // db.query('INSERT INTO users (email, password, address, phone) VALUES (?, ?, ?, ?)', [email, password, address, phone])
    // .then(() => {
    //     res.json({ success: true, message: 'Hesap başarıyla oluşturuldu!' });
    // })
    // .catch(error => {
    //     res.status(500).json({ success: false, message: 'Veritabanı hatası', error });
    // });

    // Şimdilik sadece basit bir yanıt döndürüyoruz
    res.json({ success: true, message: 'Hesap başarıyla oluşturuldu!' });
});

// Sunucu başlatma
const PORT = process.env.PORT || 3000; // Render ortamında PORT kullanılır
app.listen(PORT, () => {
    console.log(`Sunucu ${PORT} portunda çalışıyor`);
});
