const express = require('express');
const app = express();
app.use(express.json());

const PORT = process.env.PORT || 3000; // Render'da PORT ortam değişkenini kullan

app.post('/create_account', (req, res) => {
    const { email, password, address, phone } = req.body;

    // Veritabanı işlemleri burada yapılır
    res.json({ success: true, message: 'Hesap başarıyla oluşturuldu!' });
});

app.listen(PORT, () => {
    console.log(`Sunucu ${PORT} portunda çalışıyor`);
});
