// test/models.test.js
const userModel = require('../src/models/userModel');

describe('User Model', () => {
  it('should fetch users', async () => {
    const users = await userModel.getUsers();
    expect(Array.isArray(users)).toBe(true);
  });
});

