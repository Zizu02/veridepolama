// src/models/userModel.js
const { Pool } = require('pg');
const pool = new Pool();

const getUsers = async () => {
  const result = await pool.query('SELECT * FROM users');
  return result.rows;
};

const createUser = async (user) => {
  const result = await pool.query(
    'INSERT INTO users (name, email) VALUES ($1, $2) RETURNING *',
    [user.name, user.email]
  );
  return result.rows[0];
};

module.exports = {
  getUsers,
  createUser
};

