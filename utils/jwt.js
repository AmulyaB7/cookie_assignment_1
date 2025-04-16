const jwt = require('jsonwebtoken');
const { jwtSecret } = require('../config/keys');

function generateToken(payload) {
  return jwt.sign(payload, jwtSecret, { algorithm: 'HS256', expiresIn: '1h' });
}

function verifyToken(token) {
  try {
    return jwt.verify(token, jwtSecret);
  } catch (err) {
    return null;
  }
}

module.exports = { generateToken, verifyToken };
