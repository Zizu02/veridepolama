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

app.get('/account', async (req, res) => {
    // Kimlik doğrulama kontrolü yapılmalı
    // Kullanıcı kimlik doğrulama bilgileri kontrol edilmelidir

    const userId = req.user.id; // Kimlik doğrulama bilgisiyle kullanıcının ID'si alınmalı

    try {
        const result = await pool.query('SELECT email, address, phone FROM "user" WHERE id = $1', [userId]);
        res.json(result.rows[0]);
    } catch (err) {
        console.error('Sunucu hatası:', err);
        res.status(500).json({ success: false, message: 'Bir hata oluştu!' });
    }
});

app.put('/update_account', async (req, res) => {
    const { email, password, address, phone } = req.body;
    
    // Kimlik doğrulama kontrolü yapılmalı
    // Kullanıcı kimlik doğrulama bilgileri kontrol edilmelidir

    const userId = req.user.id; // Kimlik doğrulama bilgisiyle kullanıcının ID'si alınmalı

    try {
        await pool.query(
            'UPDATE "user" SET email = $1, password_hash = $2, address = $3, phone = $4 WHERE id = $5',
            [email, password, address, phone, userId]
        );
        res.json({ success: true, message: 'Bilgiler başarıyla güncellendi!' });
    } catch (err) {
        console.error('Sunucu hatası:', err);
        res.status(500).json({ success: false, message: 'Bir hata oluştu!' });
    }
});

app.get('/user_info', async (req, res) => {
    // Burada, örneğin, kullanıcı bilgilerini almak için bir e-posta ile sorgu yapabilirsiniz.
    // Bu örnekte, sabit bir e-posta kullanılıyor. Gerçek uygulamada, kimlik doğrulama yapmalısınız.
    const email = 'test@example.com'; // Kullanıcının e-postasını dinamik olarak almanız gerekebilir.
    
    try {
        const result = await pool.query(
            'SELECT * FROM "user" WHERE email = $1',
            [email]
        );
        
        if (result.rows.length > 0) {
            res.json(result.rows[0]); // İlk sonucu döndür
        } else {
            res.status(404).json({ message: 'Kullanıcı bulunamadı!' });
        }
    } catch (err) {
        console.error('Sunucu hatası:', err);
        res.status(500).json({ success: false, message: 'Bir hata oluştu!' });
    }
});


app.listen(process.env.PORT || 10000, () => {
    console.log('Sunucu çalışıyor');
});
