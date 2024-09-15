// public/scripts.js
document.addEventListener('DOMContentLoaded', () => {
    const emailElement = document.getElementById('user-email');
    const addressElement = document.getElementById('user-address');
    const phoneElement = document.getElementById('user-phone');
    const passwordElement = document.getElementById('user-password');
    const updateButton = document.getElementById('update-button');

    // Kullanıcı bilgilerini alma fonksiyonu
    async function fetchUserInfo() {
        try {
            const response = await fetch('https://veridepolama.onrender.com/user_info', {
                method: 'GET',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${localStorage.getItem('authToken')}`
                }
            });

            if (!response.ok) {
                throw new Error(`HTTP error! Status: ${response.status}`);
            }

            const data = await response.json();

            if (data.success) {
                emailElement.textContent = data.user.email || 'Bilgi yüklenemedi';
                addressElement.value = data.user.address || '';
                phoneElement.value = data.user.phone || '';
                passwordElement.value = ''; // Şifre alanı boş olabilir
            } else {
                console.error('Kullanıcı bilgileri alınamadı:', data.message);
                emailElement.textContent = 'Hata: Bilgi alınamadı';
            }
        } catch (error) {
            console.error('Bir hata oluştu:', error);
            emailElement.textContent = 'Hata: Bilgi alınamadı';
        }
    }

    // Kullanıcı bilgilerini güncelleme fonksiyonu
    async function updateUserInfo() {
        try {
            const response = await fetch('https://veridepolama.onrender.com/update_user_info', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${localStorage.getItem('authToken')}`
                },
                body: JSON.stringify({
                    email: emailElement.textContent,
                    address: addressElement.value,
                    phone: phoneElement.value,
                    password: passwordElement.value
                })
            });

            if (!response.ok) {
                throw new Error(`HTTP error! Status: ${response.status}`);
            }

            const data = await response.json();

            if (data.success) {
                alert('Bilgiler başarıyla güncellendi');
            } else {
                console.error('Bilgiler güncellenemedi:', data.message);
            }
        } catch (error) {
            console.error('Bir hata oluştu:', error);
        }
    }

    // Sayfa yüklendiğinde kullanıcı bilgilerini al
    fetchUserInfo();

    // Güncelleme butonuna tıklandığında kullanıcı bilgilerini güncelle
    updateButton.addEventListener('click', updateUserInfo);
});
