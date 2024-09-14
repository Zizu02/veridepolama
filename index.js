const express = require('express');
const app = express();
const port = process.env.PORT || 3000; // Port'u çevresel değişkenden al

app.use(express.json());

app.post('/create_account', (req, res) => {
    const { email, password, address, phone } = req.body;
    // Basit yanıt
    res.json({ success: true, message: 'Hesap başarıyla oluşturuldu!' });
});

app.listen(port, () => {
    console.log(`Sunucu ${port} portunda çalışıyor`);
});
