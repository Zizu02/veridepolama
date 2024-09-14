const express = require('express');
const app = express();
const port = process.env.PORT || 3000;

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Kullanıcı kontrolcüsünü ve diğer rotaları bağlayın
const userController = require('./src/controllers/userController');
app.use('/api', userController);

app.listen(port, () => {
    console.log(`Sunucu ${port} portunda çalışıyor`);
});
