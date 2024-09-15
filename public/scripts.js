async function fetchUserInfo() {
    // localStorage'dan e-posta adresini al
    const email = localStorage.getItem('userEmail');
    
    // Eğer e-posta adresi yoksa, kullanıcıyı giriş sayfasına yönlendir
    if (!email) {
        window.location.href = '/login.html'; // Kullanıcı giriş yapmamışsa yönlendirme
        return;
    }

    // E-posta adresini sayfada göstermek için
    const emailElement = document.getElementById('userEmail');
    if (emailElement) {
        emailElement.textContent = email;
    } else {
        console.error('E-posta adresini yerleştirecek HTML öğesi bulunamadı.');
    }

    try {
        // Kullanıcı bilgilerini almak için API çağrısı yap
        const response = await fetch(`https://veridepolama.onrender.com/user_info?email=${encodeURIComponent(email)}`);
        if (!response.ok) {
            throw new Error('Ağ yanıtı düzgün değil');
        }

        const result = await response.json();
        if (result.success) {
            // Bilgileri HTML elementlerine ekle
            document.getElementById('userAddress').value = result.data.address || '';
            document.getElementById('userPhone').value = result.data.phone || '';
        } else {
            console.error(result.message);
            document.getElementById('userAddress').value = '';
            document.getElementById('userPhone').value = '';
        }
    } catch (error) {
        console.error('Bilgiler alınırken bir hata oluştu:', error);
        document.getElementById('userAddress').value = '';
        document.getElementById('userPhone').value = '';
    }
}

async function updateUserInfo() {
    const email = localStorage.getItem('userEmail');
    const address = document.getElementById('userAddress').value;
    const phone = document.getElementById('userPhone').value;

    try {
        const response = await fetch('https://veridepolama.onrender.com/update_user', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                email,
                address,
                phone
            }),
        });

        const result = await response.json();
        if (result.success) {
            alert('Bilgiler başarıyla güncellendi!');
        } else {
            console.error(result.message);
            alert('Bilgiler güncellenirken bir hata oluştu.');
        }
    } catch (error) {
        console.error('Bilgiler güncellenirken bir hata oluştu:', error);
        alert('Bir hata oluştu. Lütfen tekrar deneyin.');
    }
}

document.addEventListener('DOMContentLoaded', fetchUserInfo);
document.getElementById('updateButton').addEventListener('click', updateUserInfo);
