const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');
require('dotenv').config();

const app = express();
const pool = new Pool({
    user: process.env.DB_USER,
    host: process.env.DB_HOST,
    database: process.env.DB_NAME,
    password: process.env.DB_PASSWORD,
    port: process.env.DB_PORT || 5432, // Varsayılan port 5432
    ssl: {
        rejectUnauthorized: false // SSL sertifikalarını doğrulama, genellikle Render gibi platformlar için gereklidir
    }
});

app.use(cors({
    origin: 'https://sapphire-algae-9ajt.squarespace.com' // veya '*' (tüm kaynaklara izin vermek için)
}));

app.use(express.json());

app.post('/create_account', async (req, res) => {
    const { email, password, address, phone } = req.body;

    try {
        const result = await pool.query(
            'INSERT INTO "user" (email, password_hash, address, phone) VALUES ($1, $2, $3, $4)',
            [email, password, address, phone]
        );
        res.json({ success: true, message: 'Hesap başarıyla oluşturuldu!' });
    } catch (err) {
        console.error('Sunucu hatası:', err);
        res.status(500).json({ success: false, message: 'Bir hata oluştu!' });
    }
});

app.post('/login', async (req, res) => {
    const { email, password } = req.body;

    try {
        // Veritabanında e-posta ve şifreyi doğrula
        const result = await pool.query(
            'SELECT * FROM "user" WHERE email = $1 AND password_hash = $2',
            [email, password]
        );
        
        if (result.rows.length > 0) {
            res.json({ success: true, message: 'Giriş başarılı!' });
        } else {
            res.status(401).json({ success: false, message: 'Geçersiz e-posta veya şifre!' });
        }
    } catch (err) {
        console.error('Sunucu hatası:', err);
        res.status(500).json({ success: false, message: 'Bir hata oluştu!' });
    }
});


app.listen(process.env.PORT || 10000, () => {
    console.log('Sunucu çalışıyor');
});
