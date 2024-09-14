// src/services/userService.js
const userModel = require('../models/userModel');

const getUsers = () => {
  return userModel.getUsers();
};

const createUser = (user) => {
  return userModel.createUser(user);
};

module.exports = {
  getUsers,
  createUser
};

