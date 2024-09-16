const nodemailer = require('nodemailer');

// E-posta gönderici oluştur
const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.EMAIL_USERNAME,  // Gmail adresi
        pass: process.env.EMAIL_PASSWORD   // Gmail uygulama şifresi
    }
});

// E-posta gönderim fonksiyonu
async function sendPasswordResetEmail(to, resetLink) {
    const mailOptions = {
        from: process.env.EMAIL_USERNAME,
        to: to,
        subject: 'Şifre Sıfırlama Bağlantısı',
        text: `Şifrenizi sıfırlamak için şu bağlantıya tıklayın: ${resetLink}`,
        html: `<p>Şifrenizi sıfırlamak için <a href="${resetLink}">buraya tıklayın</a>.</p>`
    };

    try {
        await transporter.sendMail(mailOptions);
        console.log('E-posta başarıyla gönderildi:', to);
    } catch (error) {
        console.error('E-posta gönderme hatası:', error);
        throw error;
    }
}

module.exports = { sendPasswordResetEmail };
