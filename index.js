const express = require('express');
const cors = require('cors');
const app = express();

// CORS ayarları
app.use(cors({
    origin: 'https://sapphire-algae-9ajt.squarespace.com' // Bu URL'yi doğru URL ile değiştirin
}));

app.use(express.json());

// Kullanıcı oluşturma endpoint'i
app.post('/create_account', (req, res) => {
    const { email, password, address, phone } = req.body;
    // Kullanıcı veritabanına eklenir
    res.json({ success: true, message: 'Hesap başarıyla oluşturuldu!' });
});

// Port yapılandırması
const PORT = process.env.PORT || 10000; // Render'da 10000 portunu kullanmak için
app.listen(PORT, () => {
    console.log(`Sunucu ${PORT} portunda çalışıyor`);
});
