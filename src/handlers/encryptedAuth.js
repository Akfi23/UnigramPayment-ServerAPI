// src/handlers/encryptedAuth.js
const CryptoJS = require('crypto-js');

const AUTH_SECRET = process.env.AUTHORIZATION_SECRET_KEY;
const EXPECTED_BOT_TOKEN = process.env.EXPECTED_BOT_TOKEN;

/**
 * Дешифрует AES-шифртекст (строку) и возвращает plaintext или пустую строку.
 */
function decryptAuthToken(cipherText) {
  try {
    const bytes = CryptoJS.AES.decrypt(cipherText, AUTH_SECRET);
    const decrypted = bytes.toString(CryptoJS.enc.Utf8);
    return decrypted || '';
  } catch (e) {
    console.error('[ServerAPI] decryptAuthToken error:', e && e.stack ? e.stack : e);
    return '';
  }
}

/**
 * Middleware: читает Authorization Bearer <cipher>, дешифрует и сверяет с EXPECTED_BOT_TOKEN.
 */
function requireEncryptedAuth(req, res, next) {
  try {
    const auth = req.headers['authorization'] || req.headers['Authorization'] || '';
    if (!auth) {
      return res.status(403).json({ error: 'forbidden', message: 'missing authorization header' });
    }
    const parts = auth.split(' ');
    if (parts.length !== 2 || parts[0].toLowerCase() !== 'bearer') {
      return res.status(403).json({ error: 'forbidden', message: 'invalid authorization header format' });
    }

    const cipherText = parts[1].trim();
    const decrypted = decryptAuthToken(cipherText);
    if (!decrypted) {
      return res.status(403).json({ error: 'forbidden', message: 'invalid auth token (decrypt failed)' });
    }

    if (EXPECTED_BOT_TOKEN && decrypted !== EXPECTED_BOT_TOKEN) {
      console.warn('[ServerAPI] Authorization failed: decrypted token mismatch');
      return res.status(403).json({ error: 'forbidden', message: 'invalid credentials' });
    }

    // Всё ок
    next();
  } catch (e) {
    console.error('[ServerAPI] requireEncryptedAuth error:', e && e.stack ? e.stack : e);
    return res.status(500).json({ error: 'internal_server_error', message: e.message });
  }
}

module.exports = {
  requireEncryptedAuth,
  decryptAuthToken, // экспортируем на случай нужды
};
