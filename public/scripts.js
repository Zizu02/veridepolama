// scripts.js
async function fetchUserInfo() {
    const emailElement = document.getElementById('userEmail');
    const addressElement = document.getElementById('userAddress');
    const phoneElement = document.getElementById('userPhone');
    const errorMessageElement = document.getElementById('errorMessage');

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
        } else {
            errorMessageElement.textContent = 'Kullanıcı bilgileri alınamadı';
        }
    } catch (error) {
        console.error('Bir hata oluştu:', error);
        errorMessageElement.textContent = 'Bir hata oluştu: ' + error.message;
    }
}

async function updateUserInfo() {
    const emailElement = document.getElementById('userEmail');
    const addressElement = document.getElementById('userAddress');
    const phoneElement = document.getElementById('userPhone');
    const errorMessageElement = document.getElementById('errorMessage');

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
                phone: phoneElement.value
            })
        });

        if (!response.ok) {
            throw new Error(`HTTP error! Status: ${response.status}`);
        }

        const data = await response.json();

        if (data.success) {
            alert('Bilgiler başarıyla güncellendi!');
        } else {
            errorMessageElement.textContent = 'Bilgiler güncellenemedi';
        }
    } catch (error) {
        console.error('Bir hata oluştu:', error);
        errorMessageElement.textContent = 'Bir hata oluştu: ' + error.message;
    }
}

// Update işlemini butona bağla
document.getElementById('updateButton').addEventListener('click', function() {
    updateUserInfo();
});
