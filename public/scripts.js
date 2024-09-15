// Kullanıcı bilgilerini almak ve ekrana yazdırmak için
async function fetchUserInfo() {
    // localStorage'dan e-posta adresini al
    const email = localStorage.getItem('userEmail');
    
    // Eğer e-posta adresi yoksa, kullanıcıyı giriş sayfasına yönlendir
    if (!email) {
        window.location.href = '/login.html'; // veya uygun yönlendirme
        return;
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
            document.getElementById('userEmail').textContent = result.data.email || 'Bilgi yok';
            document.getElementById('userAddress').textContent = result.data.address || 'Bilgi yok';
            document.getElementById('userPhone').textContent = result.data.phone || 'Bilgi yok';
        } else {
            console.error(result.message);
            document.getElementById('userEmail').textContent = 'Bilgi alınamadı';
            document.getElementById('userAddress').textContent = 'Bilgi alınamadı';
            document.getElementById('userPhone').textContent = 'Bilgi alınamadı';
        }
    } catch (error) {
        console.error('Bilgiler alınırken bir hata oluştu:', error);
        document.getElementById('userEmail').textContent = 'Bilgi alınamadı';
        document.getElementById('userAddress').textContent = 'Bilgi alınamadı';
        document.getElementById('userPhone').textContent = 'Bilgi alınamadı';
    }
}

// Sayfa yüklendiğinde kullanıcı bilgilerini getir
window.onload = fetchUserInfo;

