const express = require('express');
const cors = require('cors');
const app = express();

app.use(cors({
    origin: 'https://sapphire-algae-9ajt.squarespace.com'
}));

app.use(express.json());

app.post('/create_account', async (req, res) => {
    const { email, password, address, phone } = req.body;
    
    try {
        // Veritabanına veri ekleme
        await pool.query(
            'INSERT INTO "user" (email, password_hash, address, phone) VALUES ($1, $2, $3, $4)',
            [email, password, address, phone]
        );
        res.json({ success: true, message: 'Hesap başarıyla oluşturuldu!' });
    } catch (err) {
        console.error('Veritabanı hatası:', err);
        res.status(500).json({ success: false, message: 'Bir hata oluştu!' });
    }
});



app.listen(process.env.PORT || 3000, () => {
    console.log(`Sunucu ${process.env.PORT || 3000} portunda çalışıyor`);
});
