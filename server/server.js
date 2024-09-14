const express = require('express');
const app = express();
const port = process.env.PORT || 3000; // Port ayarı

app.use(express.json()); // JSON formatındaki verileri işlemek için

// Kullanıcı oluşturma endpoint'i
app.post('/create_account', (req, res) => {
    const { email, password, address, phone } = req.body;

    // Veritabanı bağlantısını kullanarak kullanıcıyı ekleyebilirsiniz
    // db.query('INSERT INTO users (email, password, address, phone) VALUES (?, ?, ?, ?)', [email, password, address, phone])
    // .then(() => {
    //     res.json({ success: true, message: 'Hesap başarıyla oluşturuldu!' });
    // })
    // .catch(error => {
    //     res.status(500).json({ success: false, message: 'Veritabanı hatası', error });
    // });

    // Şu anda sadece örnek bir yanıt döndürüyoruz
    res.json({ success: true, message: 'Hesap başarıyla oluşturuldu!' });
});

// Sunucuyu başlatma
app.listen(port, () => {
    console.log(`Sunucu ${port} portunda çalışıyor`);
});

