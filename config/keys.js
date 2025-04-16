require('dotenv').config();

module.exports = {
  jwtSecret: process.env.JWT_SECRET,
  aesSecret: process.env.AES_SECRET,
  iv: process.env.AES_IV,
};
