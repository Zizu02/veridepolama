// src/controllers/userController.js
const userService = require('../services/userService');

// Kullanıcı listeleme
exports.getUsers = async (req, res) => {
  try {
    const users = await userService.getUsers();
    res.json(users);
  } catch (err) {
    res.status(500).send(err.message);
  }
};

// Kullanıcı ekleme
exports.createUser = async (req, res) => {
  try {
    const user = await userService.createUser(req.body);
    res.status(201).json(user);
  } catch (err) {
    res.status(500).send(err.message);
  }
};

