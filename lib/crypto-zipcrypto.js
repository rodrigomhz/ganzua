'use strict';

// Traditional PKWARE ZipCrypto: a 96-bit keystream PRNG. Weak by modern
// standards, still common in old archives.
//
// The file data begins with a 12-byte encryption header. After decrypting it
// with the password-seeded keystream, the last byte is a check byte:
//   - if the data-descriptor flag (bit 3) is set: high byte of the DOS mod time
//   - otherwise:                                   high byte of the CRC-32
// The check byte gives a cheap 1/256 reject; a definitive test decrypts the
// whole body, inflates it if needed, and compares CRC-32 with the entry.

const zlib = require('zlib');

const CRC_TABLE = (() => {
  const t = new Uint32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    t[n] = c >>> 0;
  }
  return t;
})();

function crc32Byte(crc, byte) {
  return (CRC_TABLE[(crc ^ byte) & 0xff] ^ (crc >>> 8)) >>> 0;
}

function crc32(buf) {
  let crc = 0xffffffff;
  for (let i = 0; i < buf.length; i++) crc = crc32Byte(crc, buf[i]);
  return (crc ^ 0xffffffff) >>> 0;
}

// Keystream state seeded from the password.
class Keys {
  constructor(password) {
    this.k0 = 0x12345678;
    this.k1 = 0x23456789;
    this.k2 = 0x34567890;
    const pw = Buffer.isBuffer(password) ? password : Buffer.from(password, 'utf8');
    for (let i = 0; i < pw.length; i++) this.update(pw[i]);
  }

  update(byte) {
    this.k0 = crc32Byte(this.k0, byte);
    this.k1 = (this.k1 + (this.k0 & 0xff)) >>> 0;
    this.k1 = (Math.imul(this.k1, 134775813) + 1) >>> 0;
    this.k2 = crc32Byte(this.k2, this.k1 >>> 24);
  }

  streamByte() {
    const temp = (this.k2 | 2) >>> 0;
    return (Math.imul(temp, temp ^ 1) >>> 8) & 0xff;
  }

  decryptByte(cipherByte) {
    const plain = (cipherByte ^ this.streamByte()) & 0xff;
    this.update(plain);
    return plain;
  }
}

// The check byte the decrypted header should end with.
function expectedCheckByte(entry) {
  if (entry.flags & 0x08) return (entry.mtime >>> 8) & 0xff;
  return (entry.crc >>> 24) & 0xff;
}

// Fast reject: decrypt the 12-byte header and test the check byte.
function checkByteMatches(entry, password) {
  const keys = new Keys(password);
  const header = entry.header;
  let last = 0;
  for (let i = 0; i < 12; i++) last = keys.decryptByte(header[i]);
  return last === expectedCheckByte(entry);
}

// Decrypt the body with a freshly seeded keystream (after consuming the header).
function decryptBody(entry, password) {
  const keys = new Keys(password);
  const header = entry.header;
  for (let i = 0; i < 12; i++) keys.decryptByte(header[i]);
  const body = entry.body;
  const out = Buffer.allocUnsafe(body.length);
  for (let i = 0; i < body.length; i++) out[i] = keys.decryptByte(body[i]);
  return out;
}

// Definitive test: check byte, then full decrypt + inflate + CRC-32 compare.
function verifyPassword(entry, password, { fast = false } = {}) {
  if (!checkByteMatches(entry, password)) return false;
  if (fast) return true;
  let plain;
  try {
    const raw = decryptBody(entry, password);
    plain = entry.method === 8 ? zlib.inflateRawSync(raw) : raw;
  } catch {
    return false; // inflate failed => wrong key produced garbage
  }
  return crc32(plain) === entry.crc >>> 0;
}

// Decrypt (and inflate if needed) with a known-correct password.
function decrypt(entry, password) {
  const raw = decryptBody(entry, password);
  return entry.method === 8 ? zlib.inflateRawSync(raw) : raw;
}

module.exports = {
  crc32,
  Keys,
  expectedCheckByte,
  checkByteMatches,
  decryptBody,
  verifyPassword,
  decrypt,
};
