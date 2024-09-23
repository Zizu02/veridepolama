const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');  
const nodemailer = require('nodemailer'); 
const crypto = require('crypto');
const hmacSHA256 = require('crypto-js/hmac-sha256');
const Base64 = require('crypto-js/enc-base64'); 
const axios = require('axios'); // HTTP istekleri için axios'u kullanacağız
const QRCode = require('qrcode');
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

const MERCHANT_ID = '492579';
const MERCHANT_KEY = 'Gxm6ww6x6hbPJmg6';
const MERCHANT_SALT = 'RbuMk9kDZ2bCa5K2';

app.use(cors({
    origin: 'https://sapphire-algae-9ajt.squarespace.com', // Sitenizin domaini
    methods: ['GET', 'POST', 'PUT'],
    credentials: true
}));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

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




// JWT oluşturma fonksiyonu
function generateToken(userId) {
    console.log('JWT token oluşturuluyor...');
    const token = jwt.sign({ userId }, process.env.JWT_SECRET, { expiresIn: '1h' });
    console.log('JWT token oluşturuldu:', token);
    return token;
}


function authenticateToken(req, res, next) {
    console.log('JWT doğrulama başlıyor...');
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    
    if (token == null) {
        console.log('Token yok.');
        return res.sendStatus(401);
    }

    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) {
            console.log('JWT doğrulama hatası:', err.message);
            return res.sendStatus(403);
        }

        req.user = user;
        console.log('JWT doğrulandı:', user);
        next();
    });
}


// PayTR Token oluşturma fonksiyonu
function createPaytrToken(user_ip, merchant_oid, email, payment_amount, user_basket, no_installment, max_installment, currency, test_mode) {
    console.log('Sepet encode ediliyor...');
    const encodedBasket = Buffer.from(JSON.stringify(user_basket)).toString('base64');
    console.log('Base64 Encode Edilmiş Sepet:', encodedBasket);

    console.log('Hash string oluşturuluyor...');
    const hash_str = [
        MERCHANT_ID,
        user_ip,
        merchant_oid,
        email,
        payment_amount,
        encodedBasket,
        no_installment,
        max_installment,
        currency,
        test_mode
    ].join('');

    console.log('Oluşturulan Hash String:', hash_str);

    console.log('PayTR Token oluşturuluyor...');
    const paytr_token = hash_str + MERCHANT_SALT;
    const token = crypto.createHmac('sha256', MERCHANT_KEY).update(paytr_token).digest('base64');
    console.log('Oluşturulan PayTR Token:', token);

    return token;
}


// Kullanıcının gerçek IP'sini almak için fonksiyon
function getRealIp(req) {
    console.log('Gerçek IP adresi alınıyor...');
    const forwarded = req.headers['x-forwarded-for'];
    const ip = forwarded ? forwarded.split(/, /)[0] : req.connection.remoteAddress;
    console.log('Gerçek IP adresi:', ip);
    return ip;
}



// Benzersiz merchant_oid oluşturma fonksiyonu
function generateMerchantOid() {
    console.log('Benzersiz merchant_oid oluşturuluyor...');
    const timestamp = new Date().getTime().toString(); // Zaman damgasını alır
    const merchantOid = 'oid' + timestamp; // Alfanumerik bir merchant_oid oluşturur
    console.log('Oluşturulan merchant_oid:', merchantOid);
    return merchantOid;
}

// QR kod oluşturma fonksiyonu
function generateQRCodeForTable(tableNumber) {
    const url = `https://veridepolama.onrender.com/order/${tableNumber}`; // Her masanın URL'si
    return new Promise((resolve, reject) => {
        QRCode.toDataURL(url, (err, url) => {
            if (err) reject(err);
            resolve(url);
        });
    });
}

// PayTR ödeme oluşturma endpointi
app.post('/create_payment', async (req, res) => {
    // QR kod siparişi olup olmadığını kontrol et
    const { email, address, phone, items, totalAmount, isQrCodeOrder } = req.body;

    if (!isQrCodeOrder) {
        // Eğer QR kod siparişi değilse, JWT doğrulaması yap
        const authHeader = req.headers['authorization'];
        const token = authHeader && authHeader.split(' ')[1];
        
        if (!token) {
            return res.status(401).json({ success: false, message: 'Token bulunamadı.' });
        }

        try {
            // JWT doğrulama
            const decoded = jwt.verify(token, process.env.JWT_SECRET);
            req.user = decoded;
            console.log('JWT doğrulandı:', decoded);
        } catch (err) {
            return res.status(403).json({ success: false, message: 'Geçersiz veya süresi dolmuş token.' });
        }
    }

    console.log('Ödeme oluşturma işlemi başladı...');
    const userId = req.user?.userId || null;  // QR kod siparişinde userId olmayabilir

    if (userId) {
        console.log('Kullanıcı ID:', userId);
    }

    try {
        console.log('Ödeme isteği alındı:', { email, address, phone, items });

        const verifiedItems = [];
        let totalAmountInCents = 0;

        for (const item of items) {
            console.log(`Ürün kontrol ediliyor: ${item.name}`);
            const product = await pool.query('SELECT price FROM products WHERE name = $1', [item.name]);

            if (product.rows.length > 0) {
                const price = product.rows[0].price;
                totalAmountInCents += price * item.quantity * 100;
                verifiedItems.push([item.name, "Ürün açıklaması", price * 100]);
                console.log('Ürün onaylandı:', item.name, price);
            } else {
                console.error('Ürün bulunamadı:', item.name);
                return res.status(400).json({ success: false, message: 'Ürün bulunamadı: ' + item.name });
            }
        }

        console.log('Toplam tutar hesaplandı:', totalAmountInCents);

        // Dış IP kontrolü
        const ipv4 = getRealIp(req);
        console.log('Kullanıcı IP adresi:', ipv4);

        const merchantOid = generateMerchantOid();
        const token = createPaytrToken(ipv4, merchantOid, email, totalAmountInCents, verifiedItems, 0, 12, 'TL', 1);

        console.log('PayTR Token oluşturuldu:', token);

        // PayTR API isteği (application/x-www-form-urlencoded formatı)
        console.log('PayTR API isteği yapılıyor...');
        
        const formData = new URLSearchParams();
        formData.append('merchant_id', MERCHANT_ID);
        formData.append('user_ip', ipv4);
        formData.append('merchant_oid', merchantOid);
        formData.append('email', email);
        formData.append('payment_amount', totalAmountInCents);
        formData.append('user_basket', Buffer.from(JSON.stringify(verifiedItems)).toString('base64'));
        formData.append('paytr_token', token);
        formData.append('no_installment', '0');
        formData.append('max_installment', '12');
        formData.append('user_name', "John Doe"); // Gerçek kullanıcı adını kullanın
        formData.append('user_address', address);
        formData.append('user_phone', phone);
        formData.append('merchant_ok_url', "https://sapphire-algae-9ajt.squarespace.com/cart");
        formData.append('merchant_fail_url', "https://sapphire-algae-9ajt.squarespace.com/cart");
        formData.append('timeout_limit', '30');
        formData.append('currency', "TL");
        formData.append('test_mode', '1');

        const response = await axios.post('https://www.paytr.com/odeme/api/get-token', formData.toString(), {
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded'
            }
        });

        console.log("PayTR API yanıt kodu:", response.status);
        console.log("PayTR API yanıt verisi:", response.data);

        if (response.data.status === 'success') {
            res.status(200).json({ success: true, token: response.data.token });
        } else {
            console.error("PayTR API hatası:", response.data);
            res.status(500).json({ success: false, message: 'Ödeme işlemi sırasında bir hata oluştu!' });
        }

    } catch (error) {
        if (error.response) {
            console.error('PayTR API hatası:', error.response.status, error.response.data);
        } else {
            console.error('Sunucu hatası:', error.message);
        }
        res.status(500).json({ success: false, message: 'Bir hata oluştu!' });
    }
});



// Ödeme onay callback endpointi (PayTR geri dönüş yapar)
// Bildirim URL'si
app.post('/paytr_callback', (req, res) => {
    const {
        merchant_oid,
        status,
        total_amount,
        hash,
        payment_type,
        currency,
        test_mode,
        failed_reason_code,
        failed_reason_msg
    } = req.body;

    // Gelen verileri loglayalım
    console.log('PayTR Bildirimi Alındı:', req.body);

    // Hash doğrulama için gelen verilerle kendi hash'imizi oluşturalım
    const hash_str = [
        merchant_oid,
        process.env.MERCHANT_SALT,
        status,
        total_amount
    ].join('');

    // Kendi oluşturduğumuz hash değeri
    const generated_hash = crypto.createHmac('sha256', process.env.MERCHANT_KEY)
        .update(hash_str)
        .digest('base64');

    // Hash eşleşmesini kontrol edin
    if (generated_hash !== hash) {
        console.error('Hash doğrulaması başarısız!');
        return res.status(400).send('Hash doğrulaması başarısız');
    }

    // Başarılı ödeme durumu
    if (status === 'success') {
        console.log(`Sipariş başarılı: ${merchant_oid}, Tutar: ${total_amount}`);
        // Siparişi onaylayın veya işleyin
    } else {
        // Başarısız ödeme durumu
        console.log(`Sipariş başarısız: ${merchant_oid}, Sebep: ${failed_reason_msg}`);
        // Siparişi iptal edin veya işleyin
    }

    // PayTR'a OK yanıtını gönderin (aksi takdirde işlem onaylanmaz)
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
app.put('/update_order_status', async (req, res) => {
    const { orderId, status, isQrCodeOrder } = req.body;

    try {
        let result;
        
        if (isQrCodeOrder) {
            // QR kodlu siparişlerin tablosunda durum güncelleniyor
            result = await pool.query(
                'UPDATE table_orders SET status = $1 WHERE id = $2 RETURNING *',
                [status, orderId]
            );
        } else {
            // Normal siparişlerin tablosunda durum güncelleniyor
            result = await pool.query(
                'UPDATE orders SET status = $1 WHERE id = $2 RETURNING *',
                [status, orderId]
            );
        }

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
    const isQrCodeOrder = req.query.isQrCodeOrder; // İstemciden QR kod siparişi olup olmadığını alıyoruz
    let userId;

    if (!isQrCodeOrder) {
        userId = req.user.userId;  // Normal siparişlerde token'dan kullanıcı ID'si alınıyor
    }

    try {
        let result;

        if (isQrCodeOrder) {
            // QR kodlu siparişler için tabloyu kullanıyoruz
            result = await pool.query(
                `SELECT id, items, total_amount, status, created_at 
                 FROM table_orders 
                 ORDER BY created_at DESC`
            );
        } else {
            // Normal siparişler için tabloyu kullanıyoruz
            result = await pool.query(
                `SELECT id, items, total_amount, status, created_at 
                 FROM orders 
                 WHERE user_id = $1 
                 ORDER BY created_at DESC`,
                [userId]
            );
        }

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


// Masaya özel QR kodu oluşturma endpoint'i
app.get('/generate-qr/:tableNumber', (req, res) => {
    const tableNumber = req.params.tableNumber;
    const orderUrl = `https://sapphire-algae-9ajt.squarespace.com/qrkodsiparisi?table=${tableNumber}`; // Sipariş URL'si masa bilgisiyle

    // QR kodunu oluştur
    QRCode.toDataURL(orderUrl, (err, qrCode) => {
        if (err) {
            console.error('QR kod oluşturulurken hata:', err);
            return res.status(500).json({ success: false, message: 'QR kodu oluşturulamadı!' });
        }

        // QR kodu başarıyla oluşturuldu, geri döndürüyoruz
        res.send(`
            <h2>Masa ${tableNumber} için QR Kodu</h2>
            <img src="${qrCode}" alt="Masa ${tableNumber} için QR Kodu" />
        `);
    });
});



// Masaya özel sipariş endpoint'i
app.post('/order/:tableNumber', async (req, res) => {
    const tableNumber = req.params.tableNumber; // QR koddan gelen masa numarası
    const { items, totalAmount } = req.body;    // Sipariş detayları

    console.log(`Masa ${tableNumber} için sipariş alındı.`);
    console.log('Sipariş Detayları:', { items, totalAmount });

    try {
        // Siparişi veritabanına kaydetme
        const result = await pool.query(
            'INSERT INTO table_orders (table_number, items, total_amount) VALUES ($1, $2, $3) RETURNING *',
            [tableNumber, JSON.stringify(items), totalAmount]
        );
        res.json({ success: true, message: 'Sipariş başarıyla alındı!', order: result.rows[0] });
    } catch (error) {
        console.error('Sipariş kaydedilirken hata:', error);
        res.status(500).json({ success: false, message: 'Sipariş alınırken bir hata oluştu.' });
    }
});


app.get('/qrcodes', async (req, res) => {
    const tableNumbers = [1, 2, 3, 4, 5]; // Masalar numaraları
    const qrCodes = await Promise.all(tableNumbers.map(num => generateQRCodeForTable(num)));

    let html = '<h1>QR Kodlar</h1>';
    qrCodes.forEach((qrCode, index) => {
        html += `<h2>Masa ${index + 1}</h2><img src="${qrCode}" />`;
    });

    res.send(html);
});

// Ürünleri veritabanından çeken endpoint
app.get('/products', async (req, res) => {
    try {
        const result = await pool.query('SELECT name, price FROM products');
        res.json({ success: true, products: result.rows });
    } catch (error) {
        console.error('Ürünler alınırken hata:', error);
        res.status(500).json({ success: false, message: 'Ürünler alınamadı!' });
    }
});

// QR Kodlu siparişleri listeleme endpoint'i
app.get('/table_orders', async (req, res) => {
    try {
        console.log("QR kod siparişleri sorgusu başlıyor...");
        const result = await pool.query(
            `SELECT id, table_number, items, total_amount, status, created_at 
             FROM table_orders 
             ORDER BY created_at DESC`
        );
        console.log("Sorgu başarılı, sonuçlar:", result.rows);

        if (result.rows.length > 0) {
            res.json({ success: true, orders: result.rows });
        } else {
            res.json({ success: true, orders: [], message: "Herhangi bir QR kodlu sipariş bulunamadı." });
        }
    } catch (err) {
        console.error('Sunucu hatası:', err);
        res.status(500).json({ success: false, message: 'Bir hata oluştu!' });
    }
});



app.listen(3000, () => {
    console.log('Server is running on port 3000');
});
