async function fetchUserInfo() {
    const email = localStorage.getItem('userEmail');
    
    if (!email) {
        window.location.href = '/login.html'; // veya uygun yönlendirme
        return;
    }

    try {
        const response = await fetch(`https://veridepolama.onrender.com/user_info?email=${encodeURIComponent(email)}`);
        if (!response.ok) {
            throw new Error('Ağ yanıtı düzgün değil');
        }

        const result = await response.json();
        if (result.success) {
            document.getElementById('userEmail').textContent = result.data.email || 'Bilgi yok';
            document.getElementById('userAddress').value = result.data.address || '';
            document.getElementById('userPhone').value = result.data.phone || '';
        } else {
            console.error(result.message);
            document.getElementById('userEmail').textContent = 'Bilgi alınamadı';
            document.getElementById('userAddress').value = '';
            document.getElementById('userPhone').value = '';
        }
    } catch (error) {
        console.error('Bilgiler alınırken bir hata oluştu:', error);
        document.getElementById('userEmail').textContent = 'Bilgi alınamadı';
        document.getElementById('userAddress').value = '';
        document.getElementById('userPhone').value = '';
    }
}

async function updateUserInfo() {
    const email = localStorage.getItem('userEmail');
    const address = document.getElementById('userAddress').value;
    const phone = document.getElementById('userPhone').value;

    try {
        const response = await fetch('https://veridepolama.onrender.com/update_user_info', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ email, address, phone })
        });

        const result = await response.json();
        if (result.success) {
            alert('Bilgiler başarıyla güncellendi!');
        } else {
            alert('Bilgiler güncellenirken bir hata oluştu.');
        }
    } catch (error) {
        console.error('Bilgiler güncellenirken bir hata oluştu:', error);
        alert('Bilgiler güncellenirken bir hata oluştu.');
    }
}

window.onload = fetchUserInfo;
document.getElementById('updateButton').addEventListener('click', updateUserInfo);
