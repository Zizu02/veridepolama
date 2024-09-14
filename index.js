const express = require('express');
const app = express();

// Port numarasını çevresel değişkenden al, eğer yoksa varsayılan olarak 3000 kullan
const PORT = process.env.PORT || 3000;

app.use(express.json());

// Örnek bir endpoint
app.get('/', (req, res) => {
    res.send('Hello, World!');
});

// Uygulamayı belirtilen portta başlat
app.listen(PORT, () => {
    console.log(`Sunucu ${PORT} portunda çalışıyor`);
});
