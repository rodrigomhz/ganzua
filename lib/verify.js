'use strict';

// Scheme-agnostic verification/decryption dispatch over a parsed entry.

const aes = require('./crypto-aes');
const zc = require('./crypto-zipcrypto');

function verify(entry, password, opts = {}) {
  if (entry.encryption === 'aes') return aes.verifyPassword(entry.crypto, password, opts);
  if (entry.encryption === 'zipcrypto') return zc.verifyPassword(entry.crypto, password, opts);
  throw new Error(`la entrada "${entry.name}" no está cifrada`);
}

function decrypt(entry, password) {
  if (entry.encryption === 'aes') {
    const raw = aes.decrypt(entry.crypto, password);
    // AES entries carry the real compression method separately.
    if (entry.method === 8) return require('zlib').inflateRawSync(raw);
    return raw;
  }
  if (entry.encryption === 'zipcrypto') return zc.decrypt(entry.crypto, password);
  throw new Error(`la entrada "${entry.name}" no está cifrada`);
}

module.exports = { verify, decrypt };
