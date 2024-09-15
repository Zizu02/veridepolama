// Giriş işlemi
document.getElementById('loginForm').addEventListener('submit', async function(event) {
    event.preventDefault();
    
    const email = document.getElementById('email').value;
    const password = document.getElementById('password').value;

    try {
        const response = await fetch('https://veridepolama.onrender.com/login', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ email, password })
        });

        const result = await response.json();

        if (result.success) {
            localStorage.setItem('userEmail', email);
            window.location.href = '/hesabim.html'; // Başarılı giriş sonrası yönlendirme
        } else {
            alert(result.message);
        }
    } catch (error) {
        console.error('Giriş işlemi sırasında bir hata oluştu:', error);
        alert('Giriş işlemi sırasında bir hata oluştu.');
    }
});

// Hesap bilgilerini gösterme
document.addEventListener('DOMContentLoaded', async function() {
    const userEmail = localStorage.getItem('userEmail');

    if (!userEmail) {
        window.location.href = '/login.html'; // Eğer kullanıcı e-posta bilgisi yoksa giriş sayfasına yönlendir
        return;
    }

    document.getElementById('userEmail').textContent = userEmail;

    try {
        const response = await fetch('https://veridepolama.onrender.com/user_info', {
            method: 'GET',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${userEmail}`
            }
        });

        if (response.ok) {
            const userData = await response.json();
            // Hesap bilgilerini güncelle
            document.getElementById('userAddress').textContent = userData.address || 'Adres bilgisi yok';
            document.getElementById('userPhone').textContent = userData.phone || 'Telefon bilgisi yok';
        } else {
            throw new Error('Kullanıcı bilgileri alınırken bir hata oluştu');
        }
    } catch (error) {
        console.error('Hesap bilgileri alınırken bir hata oluştu:', error);
        document.getElementById('error').textContent = 'Bilgiler alınırken bir hata oluştu.';
    }
});


