const fetch = require('node-fetch');

const API_URL = 'https://sapphire-algae-9ajt.squarespace.com/api/1.0/forms'; // Gerçek API URL'si
const API_KEY = 'e378efab-d2f5-48dc-b671-b299d99b3a33'; // Gerçek API anahtarınız

const getFormData = async () => {
  try {
    const response = await fetch(API_URL, {
      method: 'GET',
      headers: {
        'Authorization': `Bearer ${API_KEY}`,
        'Content-Type': 'application/json'
      }
    });

    if (!response.ok) {
      throw new Error(`HTTP error! Status: ${response.status}`);
    }

    const data = await response.json();
    console.log(data);
  } catch (error) {
    console.error('Error fetching form data:', error);
  }
};

getFormData();
