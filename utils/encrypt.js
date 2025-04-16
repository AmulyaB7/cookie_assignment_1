const crypto = require('crypto');
const { aesSecret, iv } = require('../config/keys');

function encryptData(data) {
  const cipher = crypto.createCipheriv('aes-256-cbc', Buffer.from(aesSecret), iv);
  let encrypted = cipher.update(JSON.stringify(data), 'utf8', 'hex');
  encrypted += cipher.final('hex');
  return encrypted;
}

function decryptData(encrypted) {
  const decipher = crypto.createDecipheriv('aes-256-cbc', Buffer.from(aesSecret), iv);
  let decrypted = decipher.update(encrypted, 'hex', 'utf8');
  decrypted += decipher.final('utf8');
  return JSON.parse(decrypted);
}

module.exports = { encryptData, decryptData };
