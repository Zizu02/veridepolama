const express = require('express');
const router = express.Router();
const userService = require('../services/userService');

// Kullanıcı bilgilerini döndüren endpoint
router.get('/get_user_info', async (req, res) => {
    const email = req.query.email;
    try {
        const userInfo = await userService.getUserInfoByEmail(email);
        if (userInfo) {
            res.json({ success: true, user_info: userInfo });
        } else {
            res.json({ success: false, message: 'Kullanıcı bulunamadı' });
        }
    } catch (error) {
        res.status(500).json({ success: false, message: 'Sunucu hatası', error });
    }
});

module.exports = router;
