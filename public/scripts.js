async function fetchUserInfo() {
    const email = localStorage.getItem('userEmail');
    
    if (!email) {
        console.error('E-posta adresi bulunamadı. Kullanıcı giriş yapmamış olabilir.');
        window.location.href = '/login.html'; // Kullanıcı giriş yapmamışsa yönlendirme
        return;
    }

    const emailElement = document.getElementById('userEmail');
    if (emailElement) {
        emailElement.textContent = 'Yükleniyor...'; // Veriler yüklenene kadar "Yükleniyor..." yaz
    } else {
        console.error('E-posta adresini yerleştirecek HTML öğesi bulunamadı.');
    }

    try {
        const response = await fetch(`https://veridepolama.onrender.com/user_info?email=${encodeURIComponent(email)}`);
        if (!response.ok) {
            throw new Error('Ağ yanıtı düzgün değil: ' + response.status);
        }

        const result = await response.json();
        if (result.success) {
            if (emailElement) {
                emailElement.textContent = email; // Başarıyla alındıysa e-posta adresini güncelle
            }
            document.getElementById('userAddress').value = result.data.address || '';
            document.getElementById('userPhone').value = result.data.phone || '';
        } else {
            console.error('Bilgiler alınırken bir hata oluştu:', result.message);
            if (emailElement) {
                emailElement.textContent = 'E-posta bilgisi alınamadı'; // Bilgi alınamadıysa gösterilecek mesaj
            }
        }
    } catch (error) {
        console.error('Hata:', error);
        if (emailElement) {
            emailElement.textContent = 'E-posta bilgisi alınamadı'; // Hata durumunda gösterilecek mesaj
        }
    }
}

document.addEventListener('DOMContentLoaded', fetchUserInfo);

document.getElementById('updateButton').addEventListener('click', async () => {
    const email = localStorage.getItem('userEmail');
    const address = document.getElementById('userAddress').value;
    const phone = document.getElementById('userPhone').value;
    const password = document.getElementById('userPassword').value;

    try {
        const response = await fetch('https://veridepolama.onrender.com/update_user', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ email, address, phone, password }),
        });
        
        const result = await response.json();
        if (result.success) {
            console.log('Bilgiler başarıyla güncellendi!');
        } else {
            console.error('Bilgiler güncellenirken bir hata oluştu:', result.message);
        }
    } catch (error) {
        console.error('Hata:', error);
    }
});
