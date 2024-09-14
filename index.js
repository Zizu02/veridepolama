const express = require('express');
const app = express();
const port = process.env.PORT || 3000; // PORT değişkenini kullan, yoksa 3000 olarak ayarla

app.listen(port, () => {
    console.log(`Sunucu ${port} portunda çalışıyor`);
});

