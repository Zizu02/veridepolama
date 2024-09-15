const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');  // JWT için jsonwebtoken kütüphanesi
require('dotenv').config();

const app = express();
const pool = new Pool({
    user: process.env.DB_USER,
    host: process.env.DB_HOST,
    database: process.env.DB_NAME,
    password: process.env.DB_PASSWORD,
    port: process.env.DB_PORT || 5432,
    ssl: {
        rejectUnauthorized: false
    }
});

app.use(cors({
    origin: 'https://sapphire-algae-9ajt.squarespace.com' // veya '*' (tüm kaynaklara izin vermek için)
}));
app.use(express.json());

// JWT oluşturma fonksiyonu
function generateToken(userId) {
    return jwt.sign({ userId }, process.env.JWT_SECRET, { expiresIn: '1h' });  // 1 saat geçerli bir token
}

// JWT doğrulama fonksiyonu
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (token == null) return res.sendStatus(401);  // Token yoksa yetkisiz

    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) return res.sendStatus(403);  // Token doğrulanamazsa yasaklı
        req.user = user;  // Kullanıcı bilgilerini isteğe ekle
        next();
    });
}

// Hesap oluşturma
app.post('/create_account', async (req, res) => {
    const { email, password, address, phone } = req.body;

    try {
        console.log('Hesap oluşturma denemesi:', email);

        // Kullanıcı olup olmadığını kontrol et
        const userExists = await pool.query('SELECT * FROM "user" WHERE email = $1', [email]);

        if (userExists.rows.length > 0) {
            return res.status(400).json({ success: false, message: 'Bu e-posta adresi zaten kayıtlı!' });
        }

        // Şifreyi hash'leme
        const hashedPassword = await bcrypt.hash(password, 10);
        console.log('Hashlenmiş şifre:', hashedPassword);

        // Kullanıcıyı veritabanına ekle
        const result = await pool.query(
            'INSERT INTO "user" (email, password_hash, address, phone) VALUES ($1, $2, $3, $4)',
            [email, hashedPassword, address, phone]
        );

        console.log('Kullanıcı başarıyla oluşturuldu:', result);
        res.json({ success: true, message: 'Hesap başarıyla oluşturuldu!' });

    } catch (err) {
        console.error('Sunucu hatası:', err);
        res.status(500).json({ success: false, message: 'Bir hata oluştu!' });
    }
});

// Giriş işlemi sırasında şifre doğrulama
app.post('/login', async (req, res) => {
    const { email, password } = req.body;

    try {
        console.log('Giriş denemesi:', email);  // Loglama ekleyerek hangi e-posta ile giriş yapıldığını görebiliriz
        const result = await pool.query('SELECT * FROM "user" WHERE email = $1', [email]);

        if (result.rows.length > 0) {
            const user = result.rows[0];
            console.log('Kullanıcı bulundu:', user);  // Veritabanından dönen kullanıcıyı loglayın
            
            // Şifre doğrulama
            const passwordMatch = await bcrypt.compare(password, user.password_hash);
            console.log('Şifre doğru mu:', passwordMatch);  // Şifrenin doğru olup olmadığını loglayın

            if (passwordMatch) {
                const token = generateToken(user.id);
                res.json({ success: true, token, message: 'Giriş başarılı!' });
            } else {
                console.log('Geçersiz şifre');
                res.status(401).json({ success: false, message: 'Geçersiz e-posta veya şifre!' });
            }
        } else {
            console.log('Kullanıcı bulunamadı');
            res.status(401).json({ success: false, message: 'Geçersiz e-posta veya şifre!' });
        }
    } catch (err) {
        console.error('Sunucu hatası:', err);  // Hatanın tam olarak ne olduğunu logla
        res.status(500).json({ success: false, message: 'Bir hata oluştu!' });
    }
});

// Kullanıcı bilgilerini getirme (kimlik doğrulama gerekli)
app.get('/user_info', authenticateToken, async (req, res) => {
    const userId = req.user.userId;  // Token'dan kullanıcı ID'si alınır

    try {
        const result = await pool.query('SELECT email, address, phone FROM "user" WHERE id = $1', [userId]);
        if (result.rows.length > 0) {
            res.json({ success: true, user: result.rows[0] });
        } else {
            res.status(404).json({ success: false, message: 'Kullanıcı bulunamadı!' });
        }
    } catch (err) {
        console.error('Sunucu hatası:', err);
        res.status(500).json({ success: false, message: 'Bir hata oluştu!' });
    }
});

// Kullanıcı bilgilerini güncelleme (kimlik doğrulama gerekli)
app.put('/update_account', authenticateToken, async (req, res) => {
    const { email, password, address, phone } = req.body;
    const userId = req.user.userId;  // Token'dan kullanıcı ID'si alınır

    try {
        const hashedPassword = await bcrypt.hash(password, 10);  // Şifreyi tekrar hash'le
        await pool.query(
            'UPDATE "user" SET email = $1, password_hash = $2, address = $3, phone = $4 WHERE id = $5',
            [email, hashedPassword, address, phone, userId]
        );
        res.json({ success: true, message: 'Bilgiler başarıyla güncellendi!' });
    } catch (err) {
        console.error('Sunucu hatası:', err);
        res.status(500).json({ success: false, message: 'Bir hata oluştu!' });
    }
});

app.listen(process.env.PORT || 10000, () => {
    console.log('Sunucu çalışıyor');
});

