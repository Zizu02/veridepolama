const express = require('express');
const router = express.Router();
const { getUserInfoByEmail } = require('../models/userModel');

// Kullanıcı bilgilerini e-posta adresi ile almak için endpoint
router.get('/get_user_info', async (req, res) => {
    const email = req.query.email;

    if (!email) {
        return res.status(400).json({ success: false, message: 'E-posta parametresi eksik' });
    }

    try {
        const user = await getUserInfoByEmail(email);
        if (user) {
            res.json({ success: true, user_info: user });
        } else {
            res.status(404).json({ success: false, message: 'Kullanıcı bulunamadı' });
        }
    } catch (error) {
        res.status(500).json({ success: false, message: 'Sunucu hatası' });
    }
});

module.exports = router;
