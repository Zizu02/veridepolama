// src/controllers/userController.js
const express = require('express');
const { Pool } = require('pg');
require('dotenv').config();

const router = express.Router();
const pool = new Pool({
    user: process.env.DB_USER,
    host: process.env.DB_HOST,
    database: process.env.DB_NAME,
    password: process.env.DB_PASSWORD,
    port: process.env.DB_PORT,
    ssl: { rejectUnauthorized: false }
});

// Giriş yapma
router.post('/login', async (req, res) => {
    const { email, password } = req.body;

    try {
        const result = await pool.query('SELECT * FROM "user" WHERE email = $1 AND password_hash = $2', [email, password]);

        if (result.rows.length > 0) {
            const user = result.rows[0];
            const token = generateToken(user.id); // Kullanıcı ID'sine göre bir token oluştur
            res.json({ success: true, token });
        } else {
            res.status(401).json({ success: false, message: 'Geçersiz e-posta veya şifre' });
        }
    } catch (error) {
        console.error('Giriş hatası:', error);
        res.status(500).json({ success: false, message: 'Sunucu hatası' });
    }
});

// Kullanıcı bilgilerini alma
router.get('/user_info', async (req, res) => {
    const userId = verifyToken(req.headers.authorization); // Token doğrulama

    if (!userId) {
        return res.status(401).json({ success: false, message: 'Geçersiz token' });
    }

    try {
        const result = await pool.query('SELECT email, address, phone FROM "user" WHERE id = $1', [userId]);
        if (result.rows.length > 0) {
            res.json({ success: true, user: result.rows[0] });
        } else {
            res.status(404).json({ success: false, message: 'Kullanıcı bulunamadı' });
        }
    } catch (error) {
        console.error('Kullanıcı bilgileri hatası:', error);
        res.status(500).json({ success: false, message: 'Sunucu hatası' });
    }
});

// Kullanıcı bilgilerini güncelleme
router.post('/update_user_info', async (req, res) => {
    const { email, address, phone, password } = req.body;
    const userId = verifyToken(req.headers.authorization); // Token doğrulama

    if (!userId) {
        return res.status(401).json({ success: false, message: 'Geçersiz token' });
    }

    try {
        await pool.query(
            'UPDATE "user" SET email = $1, address = $2, phone = $3, password_hash = $4 WHERE id = $5',
            [email, address, phone, password, userId]
        );
        res.json({ success: true, message: 'Kullanıcı bilgileri güncellendi' });
    } catch (error) {
        console.error('Bilgi güncelleme hatası:', error);
        res.status(500).json({ success: false, message: 'Sunucu hatası' });
    }
});

module.exports = router;
