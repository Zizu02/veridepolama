const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');  
const nodemailer = require('nodemailer'); 
const hmacSHA256 = require('crypto-js/hmac-sha256');
const Base64 = require('crypto-js/enc-base64'); 
const axios = require('axios'); // HTTP istekleri için axios'u kullanacağız
require('dotenv').config();

const productsModel = require('./src/models/productsModel');
const OrdersModel = require('./src/models/ordersModel');

const { sendPasswordResetEmail } = require('./src/services/emailService');
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

// PayTR için gerekli bilgiler (ENV değişkenlerinden alınacak)
const MERCHANT_ID = process.env.MERCHANT_ID;
const MERCHANT_KEY = process.env.MERCHANT_KEY;
const MERCHANT_SALT = process.env.MERCHANT_SALT;


// Nodemailer Transporter yapılandırması
const transporter = nodemailer.createTransport({
    service: 'Gmail', 
    auth: {
        user: process.env.EMAIL_USER, 
        pass: process.env.EMAIL_PASS 
    }
});

console.log(process.env.EMAIL_USER);
console.log(process.env.EMAIL_PASS);

app.use(cors({
    origin: 'https://sapphire-algae-9ajt.squarespace.com'
}));
app.use(express.json());



// JWT oluşturma fonksiyonu
function generateToken(userId) {
    return jwt.sign({ userId }, process.env.JWT_SECRET, { expiresIn: '1h' });
}

// JWT doğrulama fonksiyonu
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (token == null) return res.sendStatus(401);

    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) return res.sendStatus(403);
        req.user = user;
        next();
    });
}

// PayTR ödeme token oluşturma fonksiyonu
function createPaytrToken(user_ip, merchant_oid, email, payment_amount, user_basket, no_installment, max_installment, currency, test_mode) {
    const hash_str = [
        PAYTR_MERCHANT_ID,
        user_ip,
        merchant_oid,
        email,
        payment_amount,
        user_basket,
        no_installment,
        max_installment,
        currency,
        test_mode
    ].join('');

    console.log('PayTR Token oluşturma verileri:', {
        PAYTR_MERCHANT_ID,
        user_ip,
        merchant_oid,
        email,
        payment_amount,
        user_basket,
        no_installment,
        max_installment,
        currency,
        test_mode
    });

    const token = Base64.stringify(hmacSHA256(hash_str + PAYTR_MERCHANT_SALT, PAYTR_MERCHANT_KEY));
    console.log('Oluşturulan PayTR Token:', token);
    
    return token;
}

// Benzersiz merchant_oid oluşturma fonksiyonu
function generateMerchantOid() {
    return 'oid_' + new Date().getTime();  // Benzersiz bir sipariş numarası
}

// PayTR ödeme oluşturma endpointi
app.post('/create_payment', authenticateToken, async (req, res) => {
    const { email, address, phone, items } = req.body;
    const userId = req.user.userId;

    try {
        // Ürünlerin fiyatlarını kontrol et ve toplamı hesapla
        const verifiedItems = [];
        let totalAmount = 0;

        // Tüm gelen bilgileri logla
        console.log("Ödeme isteği alındı:", { email, address, phone, items });

        for (const item of items) {
            console.log(`Ürün kontrol ediliyor: ${item.name}`);
            const product = await pool.query('SELECT price FROM products WHERE name = $1', [item.name]);

            if (product.rows.length > 0) {
                const price = product.rows[0].price;
                totalAmount += price * item.quantity;
                verifiedItems.push([item.name, "Ürün açıklaması", parseFloat(price) * 100]);
                console.log(`Ürün fiyatı bulundu: ${item.name}, fiyat: ${price}`);
            } else {
                console.log(`Ürün bulunamadı: ${item.name}`);
                return res.status(400).json({ success: false, message: 'Ürün bulunamadı: ' + item.name });
            }
        }

        const paymentAmountInCents = parseFloat(totalAmount) * 100;
        console.log(`Toplam ödeme miktarı hesaplandı: ${paymentAmountInCents} kuruş`);

        // PayTR API'sine ödeme isteği gönder
        const merchantOid = generateMerchantOid();
        console.log('PayTR API isteği yapılıyor...');
        console.log({
            merchant_id: PAYTR_MERCHANT_ID,
            user_ip: req.ip,
            merchant_oid: merchantOid,
            email: email,
            payment_amount: paymentAmountInCents,
            user_basket: verifiedItems,
            no_installment: 0,
            max_installment: 12,
            user_name: "John Doe",
            user_address: address,
            user_phone: phone,
            currency: "TL",
            test_mode: 1
        });

        const token = createPaytrToken(req.ip, merchantOid, email, paymentAmountInCents, verifiedItems, 0, 12, 'TL', 1);
        console.log('PayTR Token oluşturuldu:', token);

        const response = await axios.post('https://www.paytr.com/odeme/api/get-token', {
            merchant_id: PAYTR_MERCHANT_ID,
            user_ip: req.ip,
            merchant_oid: merchantOid,
            email: email,
            payment_amount: paymentAmountInCents,
            user_basket: verifiedItems,
            paytr_token: token,
            no_installment: 0,
            max_installment: 12,
            user_name: "John Doe",
            user_address: address,
            user_phone: phone,
            merchant_ok_url: "https://sapphire-algae-9ajt.squarespace.com/cart",
            merchant_fail_url: "https://sapphire-algae-9ajt.squarespace.com/cart",
            timeout_limit: 30,
            currency: "TL",
            test_mode: 1
        });

        console.log("PayTR API yanıtı:", response.data);

        if (response.data.status === 'success') {
            console.log('PayTR Token alındı:', response.data.token);
            res.json({ success: true, token: response.data.token });
        } else {
            console.log('PayTR token alınamadı. Yanıt:', response.data);
            res.status(400).json({ success: false, message: 'PayTR token alınamadı.' });
        }
    } catch (err) {
        console.error('Sunucu hatası:', err);
        res.status(500).json({ success: false, message: 'Bir hata oluştu!' });
    }
});





// Ödeme onay callback endpointi (PayTR geri dönüş yapar)
app.post('/paytr_callback', (req, res) => {
    const { merchant_oid, status, total_amount, hash } = req.body;

    const hash_str = `${merchant_oid}${MERCHANT_SALT}${status}${total_amount}`;
    const generated_hash = Base64.stringify(hmacSHA256(hash_str, MERCHANT_KEY));

    if (generated_hash !== hash) {
        return res.status(400).send('Hash doğrulaması başarısız oldu.');
    }

    if (status === 'success') {
        console.log(`Sipariş ${merchant_oid} başarılı!`);
        // Veritabanına başarıyı işleyin
    } else {
        console.log(`Sipariş ${merchant_oid} başarısız!`);
        // Başarısızlık durumunu işleyin
    }

    res.send('OK');
});

// İade talebi oluşturma
app.post('/refund', async (req, res) => {
    const { merchant_oid, return_amount, reference_no } = req.body;

    try {
        // İade token'ı oluşturma
        const paytrToken = crypto
            .createHmac('sha256', MERCHANT_KEY)
            .update(`${MERCHANT_ID}${merchant_oid}${return_amount}${PAYTR_MERCHANT_SALT}`)
            .digest('base64');

        // İade için gerekli POST verileri
        const postData = {
            merchant_id: MERCHANT_ID,
            merchant_oid: merchant_oid,
            return_amount: return_amount,
            // Eğer referans numarası sağlanmışsa gönder
            ...(reference_no && { reference_no: reference_no }),
            paytr_token: paytrToken
        };

        // PayTR iade API'sine POST isteği gönderme
        const response = await axios.post('https://www.paytr.com/odeme/iade', postData, {
            timeout: 90000 // 90 saniye timeout süresi
        });

        const result = response.data;

        // İade sonucu kontrolü
        if (result.status === 'success') {
            return res.json({
                success: true,
                message: 'İade işlemi başarılı',
                data: result
            });
        } else {
            return res.status(400).json({
                success: false,
                message: `İade başarısız: ${result.err_no} - ${result.err_msg}`
            });
        }
    } catch (error) {
        console.error('İade işlemi sırasında hata:', error);
        return res.status(500).json({
            success: false,
            message: 'İade isteği sırasında bir hata oluştu.'
        });
    }
});

// Hesap oluşturma
app.post('/create_account', async (req, res) => {
    const { email, password, address, phone } = req.body;

    try {
        console.log('Hesap oluşturma denemesi:', email);

        const userExists = await pool.query('SELECT * FROM "user" WHERE email = $1', [email]);

        if (userExists.rows.length > 0) {
            return res.status(400).json({ success: false, message: 'Bu e-posta adresi zaten kayıtlı!' });
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        console.log('Hashlenmiş şifre:', hashedPassword);

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
        const result = await pool.query('SELECT * FROM "user" WHERE email = $1', [email]);

        if (result.rows.length > 0) {
            const user = result.rows[0];
            const passwordMatch = await bcrypt.compare(password, user.password_hash);

            if (passwordMatch) {
                const token = generateToken(user.id);
                res.json({ success: true, token, message: 'Giriş başarılı!' });
            } else {
                res.status(401).json({ success: false, message: 'Geçersiz e-posta veya şifre!' });
            }
        } else {
            res.status(401).json({ success: false, message: 'Geçersiz e-posta veya şifre!' });
        }
    } catch (err) {
        console.error('Sunucu hatası:', err);
        res.status(500).json({ success: false, message: 'Bir hata oluştu!' });
    }
});

// Kullanıcı bilgilerini getirme (kimlik doğrulama gerekli)
app.get('/user_info', authenticateToken, async (req, res) => {
    const userId = req.user.userId;

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
    const userId = req.user.userId;

    try {
        let query;
        let values;

        if (password) {
            const hashedPassword = await bcrypt.hash(password, 10);
            query = 'UPDATE "user" SET email = $1, password_hash = $2, address = $3, phone = $4 WHERE id = $5';
            values = [email, hashedPassword, address, phone, userId];
        } else {
            query = 'UPDATE "user" SET email = $1, address = $2, phone = $3 WHERE id = $4';
            values = [email, address, phone, userId];
        }

        await pool.query(query, values);

        res.json({ success: true, message: 'Bilgiler başarıyla güncellendi!' });
    } catch (err) {
        console.error('Sunucu hatası:', err);
        res.status(500).json({ success: false, message: 'Bir hata oluştu!' });
    }
});

// Şifre sıfırlama e-posta gönderimi
app.post('/send_reset_link', async (req, res) => {
    const { email } = req.body;

    try {
        const user = await pool.query('SELECT * FROM "user" WHERE email = $1', [email]);

        if (user.rows.length === 0) {
            return res.status(404).json({ success: false, message: 'Bu e-posta ile kayıtlı kullanıcı bulunamadı.' });
        }

        const resetToken = jwt.sign({ email }, process.env.JWT_SECRET, { expiresIn: '1h' });
        const resetLink = `https://sapphire-algae-9ajt.squarespace.com/yeni-ifre-gir?token=${resetToken}`;

        await transporter.sendMail({
            from: process.env.EMAIL_USER,
            to: email,
            subject: 'Şifre Sıfırlama Bağlantınız',
            text: `Şifrenizi sıfırlamak için şu bağlantıya tıklayın: ${resetLink}`,
            html: `<p>Şifrenizi sıfırlamak için <a href="${resetLink}">bu bağlantıya</a> tıklayın.</p>`
        });

        res.json({ success: true, message: 'Şifre sıfırlama bağlantısı gönderildi.' });
    } catch (err) {
        console.error('E-posta gönderim hatası:', err);
        res.status(500).json({ success: false, message: 'Bir hata oluştu.' });
    }
});

// Şifre sıfırlama işlemi
app.post('/confirm_reset_password', async (req, res) => {
    const { token, newPassword } = req.body;

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        const hashedPassword = await bcrypt.hash(newPassword, 10);

        await pool.query('UPDATE "user" SET password_hash = $1 WHERE email = $2', [hashedPassword, decoded.email]);

        res.json({ success: true, message: 'Şifre başarıyla güncellendi!' });
    } catch (error) {
        console.error('Şifre sıfırlama hatası:', error);
        res.status(500).json({ success: false, message: 'Şifre sıfırlanırken bir hata oluştu.' });
    }
});

// Yeni sipariş oluşturma
app.post('/create_order', authenticateToken, async (req, res) => {
    const { items, totalAmount } = req.body; // Ürün adı ve miktarı burada alınır
    const userId = req.user.userId;

    try {
        let verifiedTotal = 0;

        for (const item of items) {
            // Ürün adını veri tabanından kontrol et
            const product = await productsModel.getProductByName(item.name);

            if (product) {
                const priceInCents = Math.round(parseFloat(product.price) * 100); // Veritabanındaki fiyatı kuruş formatına çevir
                const itemPriceInCents = Math.round(parseFloat(item.price) * 100); // DOM'dan gelen fiyatı kuruş formatına çevir

                // Her ürünün miktarına göre toplam fiyatı hesapla
                verifiedTotal += priceInCents * item.quantity;

                // Ürün fiyatı ile kullanıcının gönderdiği fiyatı kuruş formatında karşılaştır
                if (priceInCents !== itemPriceInCents) {
                    return res.status(400).json({ success: false, message: `Fiyat uyuşmazlığı: ${item.name} (Veritabanı: ${priceInCents}, DOM: ${itemPriceInCents})` });
                }
            } else {
                return res.status(400).json({ success: false, message: `Ürün bulunamadı: ${item.name}` });
            }
        }

        // Toplam tutar eşleşiyor mu kontrol et
        const verifiedTotalInCents = Math.round(parseFloat(totalAmount) * 100); // Toplam tutarı da kuruş cinsine çevir
        if (verifiedTotal !== verifiedTotalInCents) {
            return res.status(400).json({ success: false, message: 'Toplam tutar uyuşmazlığı' });
        }

        // Siparişi veritabanına kaydet
        const result = await pool.query(
            'INSERT INTO orders (user_id, items, total_amount) VALUES ($1, $2, $3) RETURNING *',
            [userId, JSON.stringify(items), totalAmount]
        );

        res.json({ success: true, message: 'Sipariş başarıyla oluşturuldu!', order: result.rows[0] });
    } catch (err) {
        console.error('Sunucu hatası:', err);
        res.status(500).json({ success: false, message: 'Bir hata oluştu!' });
    }
});




// Sipariş durumunu güncelleme (Sadece site sahibi)
// Sipariş statüsünü güncelleyen endpoint
app.put('/update_order_status', authenticateToken, async (req, res) => {
    const { orderId, status } = req.body;

    try {
        // Sipariş durumunu güncelle
        const result = await pool.query(
            'UPDATE orders SET status = $1 WHERE id = $2 RETURNING *',
            [status, orderId]
        );

        if (result.rows.length > 0) {
            res.json({
                success: true,
                message: 'Sipariş durumu başarıyla güncellendi!',
                order: result.rows[0]
            });
        } else {
            res.status(404).json({ success: false, message: 'Sipariş bulunamadı!' });
        }
    } catch (err) {
        console.error('Sunucu hatası:', err);
        res.status(500).json({ success: false, message: 'Bir hata oluştu!' });
    }
});


// Kullanıcının tüm siparişlerini çekme
app.get('/my_orders', authenticateToken, async (req, res) => {
    const userId = req.user.userId;  // Token'dan kullanıcı ID'si alınıyor

    try {
        const result = await pool.query(
            `SELECT id, items, total_amount, status, created_at 
             FROM orders 
             WHERE user_id = $1 
             ORDER BY created_at DESC`,
            [userId]
        );
        res.json({ success: true, orders: result.rows });
    } catch (err) {
        console.error('Sunucu hatası:', err);
        res.status(500).json({ success: false, message: 'Bir hata oluştu!' });
    }
});


// Site sahibinin tüm siparişleri görmesi
app.get('/all_orders', authenticateToken, async (req, res) => {
    if (!req.user.isAdmin) {
        return res.status(403).json({ success: false, message: 'Bu işlemi gerçekleştirmek için yetkiniz yok.' });
    }

    try {
        const result = await pool.query('SELECT * FROM orders ORDER BY created_at DESC');
        res.json({ success: true, orders: result.rows });
    } catch (err) {
        console.error('Sunucu hatası:', err);
        res.status(500).json({ success: false, message: 'Bir hata oluştu!' });
    }
});

// Sipariş statüsünü güncelleme ve fiyat kontrolü
app.post('/validate_order', authenticateToken, async (req, res) => {
    const { items, totalAmount } = req.body;
    const userId = req.user.userId;

    try {
        let verifiedItems = [];
        let calculatedTotal = 0;

        // Her bir ürünü kontrol et
        for (let item of items) {
            const productResult = await pool.query('SELECT price FROM products WHERE name = $1', [item.name]);
            
            if (productResult.rows.length === 0) {
                return res.status(400).json({ success: false, message: `Ürün bulunamadı: ${item.name}` });
            }

            const productPrice = productResult.rows[0].price;

            // Ürün fiyatı uyuşmuyor mu?
            if (productPrice !== item.price) {
                await pool.query('UPDATE orders SET status = $1 WHERE user_id = $2 AND id = $3', ['iptal', userId, item.orderId]);
                return res.status(400).json({ success: false, message: `Fiyat uyuşmazlığı. Ürün: ${item.name}` });
            }

            // Toplam fiyatı hesapla
            calculatedTotal += productPrice * item.quantity;

            verifiedItems.push({
                name: item.name,
                price: productPrice,
                quantity: item.quantity
            });
        }

        // Toplam fiyatlar uyuşmuyor mu?
        if (calculatedTotal !== totalAmount) {
            await pool.query('UPDATE orders SET status = $1 WHERE user_id = $2 AND id = $3', ['iptal', userId, item.orderId]);
            return res.status(400).json({ success: false, message: 'Toplam tutar uyuşmuyor. Sipariş iptal edildi.' });
        }

        // Sipariş onaylanmış duruma getiriliyor
        await pool.query('UPDATE orders SET status = $1 WHERE user_id = $2 AND id = $3', ['onaylandı', userId, item.orderId]);

        return res.json({ success: true, message: 'Sipariş onaylandı!' });

    } catch (error) {
        console.error('Sunucu hatası:', error);
        return res.status(500).json({ success: false, message: 'Bir hata oluştu.' });
    }
});




app.listen(process.env.PORT || 10000, () => {
    console.log('Sunucu çalışıyor');
});
