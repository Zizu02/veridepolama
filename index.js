const express = require('express');
const cors = require('cors');
const app = express();

app.use(cors({
    origin: 'https://sapphire-algae-9ajt.squarespace.com' // veya '*' (tüm kaynaklara izin vermek için)
}));

app.use(express.json());

app.post('/create_account', (req, res) => {
    const { email, password, address, phone } = req.body;
    // Kullanıcı veritabanına eklenir
    res.json({ success: true, message: 'Hesap başarıyla oluşturuldu!' });
});

app.listen(process.env.PORT || 3000, () => {
    console.log('Sunucu çalışıyor');
});
