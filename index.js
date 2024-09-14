const express = require('express');
const app = express();
app.use(express.json());

// Kullanıcı oluşturma endpoint'i
app.post('/create_account', (req, res) => {
    const { email, password, address, phone } = req.body;

    // Şimdilik sadece basit bir yanıt döndürüyoruz
    res.json({ success: true, message: 'Hesap başarıyla oluşturuldu!' });
});

// Sunucu başlatma
const PORT = process.env.PORT || 3000; // Render ortamında PORT kullanılır
app.listen(PORT, () => {
    console.log(`Sunucu ${PORT} portunda çalışıyor`);
});
