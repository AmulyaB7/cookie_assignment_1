require('dotenv').config();
const jwt = require('jsonwebtoken');
const crypto = require('crypto');

// AES Configuration
const algorithm = 'aes-256-cbc';
const secretKey = process.env.AES_SECRET;
const iv = process.env.AES_IV;

// Encrypt function
const encrypt = (payload) => {
  const cipher = crypto.createCipheriv(algorithm, Buffer.from(secretKey), iv);
  let encrypted = cipher.update(JSON.stringify(payload), 'utf8', 'hex');
  encrypted += cipher.final('hex');

  const token = jwt.sign({ data: encrypted }, process.env.JWT_SECRET, {
    algorithm: 'HS256',
    expiresIn: '1h'
  });

  return token;
};

// Decrypt function
const decrypt = (token) => {
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const encryptedData = decoded.data;

    const decipher = crypto.createDecipheriv(algorithm, Buffer.from(secretKey), iv);
    let decrypted = decipher.update(encryptedData, 'hex', 'utf8');
    decrypted += decipher.final('utf8');

    return JSON.parse(decrypted);
  } catch (error) {
    console.error("❌ Decryption or token verification failed:", error.message);
    return null;
  }
};

// Exports
module.exports = {
  encrypt,
  decrypt
};

// ----------- Test Run Below ------------
const user = {
  id: 1,
  username: 'Amulya',
  role: 'developer'
};

const token = encrypt(user);
console.log("🔐 Encrypted JWT Token:\n", token);

const data = decrypt(token);
if (data) {
  console.log("✅ Decrypted Payload:\n", data);
  console.log("🎉 Success");
} else {
  console.log("❌ Something went wrong");
}
