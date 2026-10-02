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
const { toBytes } = require('./encoding');

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

// Inverse CRC table: crcinvtab[msb(crctab[i])] = (crctab[i] << 8) ^ i.
const CRC_INV_TABLE = (() => {
  const t = new Uint32Array(256);
  for (let b = 0; b < 256; b++) t[CRC_TABLE[b] >>> 24] = (((CRC_TABLE[b] << 8) >>> 0) ^ b) >>> 0;
  return t;
})();

// crc32^-1: recovers x from crc32(x, b).
function crc32InvByte(crc, byte) {
  return (((crc << 8) >>> 0) ^ CRC_INV_TABLE[crc >>> 24] ^ byte) >>> 0;
}

const MULT = 0x08088405;
const MULTINV = 0xd94fa8cd;

function crc32(buf) {
  let crc = 0xffffffff;
  for (let i = 0; i < buf.length; i++) crc = crc32Byte(crc, buf[i]);
  return (crc ^ 0xffffffff) >>> 0;
}

// Keystream state seeded from the password (or from recovered internal keys).
class Keys {
  constructor(password, encoding = 'utf8') {
    this.k0 = 0x12345678;
    this.k1 = 0x23456789;
    this.k2 = 0x34567890;
    if (password === undefined || password === null) return; // estado inicial
    const pw = toBytes(password, encoding);
    for (let i = 0; i < pw.length; i++) this.update(pw[i]);
  }

  // Construye a partir de las claves internas recuperadas (k0, k1, k2), como
  // las que produce el ataque de texto plano / bkcrack.
  static fromState(k0, k1, k2) {
    const keys = new Keys();
    keys.k0 = k0 >>> 0;
    keys.k1 = k1 >>> 0;
    keys.k2 = k2 >>> 0;
    return keys;
  }

  update(byte) {
    this.k0 = crc32Byte(this.k0, byte);
    this.k1 = (this.k1 + (this.k0 & 0xff)) >>> 0;
    this.k1 = (Math.imul(this.k1, MULT) + 1) >>> 0;
    this.k2 = crc32Byte(this.k2, this.k1 >>> 24);
  }

  streamByte() {
    const temp = (this.k2 | 2) >>> 0;
    return (Math.imul(temp, temp ^ 1) >>> 8) & 0xff;
  }

  // Alias used by the plaintext attack (bkcrack naming).
  getK() {
    return this.streamByte();
  }

  decryptByte(cipherByte) {
    const plain = (cipherByte ^ this.streamByte()) & 0xff;
    this.update(plain);
    return plain;
  }

  encryptByte(plainByte) {
    const cipher = (plainByte ^ this.streamByte()) & 0xff;
    this.update(plainByte);
    return cipher;
  }

  // Roll the state back one step given the ciphertext byte c.
  updateBackward(c) {
    const oldK1 = this.k1;
    const oldK0 = this.k0;
    this.k2 = crc32InvByte(this.k2, (oldK1 >>> 24) & 0xff);
    this.k1 = (Math.imul((oldK1 - 1) >>> 0, MULTINV) - (oldK0 & 0xff)) >>> 0;
    const p = (c ^ this.getK()) & 0xff; // getK uses the just-updated k2
    this.k0 = crc32InvByte(this.k0, p);
  }

  // Roll the state back one step given the plaintext byte p directly.
  updateBackwardPlaintext(p) {
    const oldK1 = this.k1;
    const oldK0 = this.k0;
    this.k2 = crc32InvByte(this.k2, (oldK1 >>> 24) & 0xff);
    this.k1 = (Math.imul((oldK1 - 1) >>> 0, MULTINV) - (oldK0 & 0xff)) >>> 0;
    this.k0 = crc32InvByte(this.k0, p & 0xff);
  }

  // Advance forward through ciphertext[current..target) (decrypting as it goes).
  updateRange(ciphertext, current, target) {
    for (let i = current; i < target; i++) this.update((ciphertext[i] ^ this.getK()) & 0xff);
  }

  // Roll backward through ciphertext[target..current) in reverse.
  updateBackwardRange(ciphertext, current, target) {
    for (let i = current - 1; i >= target; i--) this.updateBackward(ciphertext[i]);
  }
}

// The check byte the decrypted header should end with.
function expectedCheckByte(entry) {
  if (entry.flags & 0x08) return (entry.mtime >>> 8) & 0xff;
  return (entry.crc >>> 24) & 0xff;
}

// Fast reject: decrypt the 12-byte header and test the check byte.
function checkByteMatches(entry, password, encoding = 'utf8') {
  const keys = new Keys(password, encoding);
  const header = entry.header;
  let last = 0;
  for (let i = 0; i < 12; i++) last = keys.decryptByte(header[i]);
  return last === expectedCheckByte(entry);
}

// Decrypt the body with a freshly seeded keystream (after consuming the header).
function decryptBody(entry, password, encoding = 'utf8') {
  const keys = new Keys(password, encoding);
  const header = entry.header;
  for (let i = 0; i < 12; i++) keys.decryptByte(header[i]);
  const body = entry.body;
  const out = Buffer.allocUnsafe(body.length);
  for (let i = 0; i < body.length; i++) out[i] = keys.decryptByte(body[i]);
  return out;
}

// Confirmación definitiva de la contraseña según el método de compresión.
// STORE/DEFLATE: descifra, descomprime y compara el CRC-32. Otros métodos
// (bzip2/lzma/…) no se pueden descomprimir aquí, así que se valida por la firma
// del flujo descifrado (fuerte para bzip2/lzma; para métodos desconocidos se
// acepta con el check byte, que ya pasó).
function confirmByMethod(entry, password, encoding) {
  let body;
  try {
    body = decryptBody(entry, password, encoding);
  } catch {
    return false;
  }
  if (entry.method === 0) return crc32(body) === entry.crc >>> 0;
  if (entry.method === 8) {
    try {
      return crc32(zlib.inflateRawSync(body)) === entry.crc >>> 0;
    } catch {
      return false; // inflate falló => clave incorrecta produjo basura
    }
  }
  if (entry.method === 12) {
    // BZIP2: "BZh" + nivel 1-9
    return (
      body.length >= 4 && body[0] === 0x42 && body[1] === 0x5a && body[2] === 0x68 && body[3] >= 0x31 && body[3] <= 0x39
    );
  }
  if (entry.method === 14) {
    // LZMA en ZIP: [versión(2)][propsSize(2)=5][props(5)]
    return body.length >= 4 && body.readUInt16LE(2) === 5;
  }
  return true; // método desconocido: nos quedamos con el check byte
}

// Definitive test: check byte, then confirm per compression method.
function verifyPassword(entry, password, { fast = false, encoding = 'utf8' } = {}) {
  if (!checkByteMatches(entry, password, encoding)) return false;
  if (fast) return true;
  return confirmByMethod(entry, password, encoding);
}

// Verificación cuando solo se tiene un PREFIJO del cuerpo cifrado (una "sonda"):
// check byte y, según el método, validación del flujo descifrado. Con
// `full=true` (el prefijo es el cuerpo entero) hace la confirmación definitiva
// por CRC. En DEFLATE parcial, comprueba que el prefijo descifrado inicia un
// flujo deflate válido (inflate con Z_SYNC_FLUSH); combinado con el check byte
// los falsos positivos son ínfimos, y la contraseña se confirma al descifrar
// el archivo completo en origen.
function verifyPasswordPrefix(entry, password, { encoding = 'utf8', full = false } = {}) {
  if (!checkByteMatches(entry, password, encoding)) return false;
  if (full) return confirmByMethod(entry, password, encoding);
  let body;
  try {
    body = decryptBody(entry, password, encoding);
  } catch {
    return false;
  }
  if (entry.method === 8) {
    // El prefijo descifrado debe iniciar un flujo deflate válido. Con
    // Z_SYNC_FLUSH, un prefijo correcto decodifica sin error (puede dar 0 bytes
    // si aún va por la tabla Huffman); una clave incorrecta produce basura y
    // lanza un error de datos. Un truncamiento legítimo es Z_BUF_ERROR.
    try {
      zlib.inflateRawSync(body, { finishFlush: zlib.constants.Z_SYNC_FLUSH });
      return true;
    } catch (err) {
      return err && err.code === 'Z_BUF_ERROR';
    }
  }
  if (entry.method === 12) {
    return (
      body.length >= 4 && body[0] === 0x42 && body[1] === 0x5a && body[2] === 0x68 && body[3] >= 0x31 && body[3] <= 0x39
    );
  }
  if (entry.method === 14) {
    return body.length >= 4 && body.readUInt16LE(2) === 5;
  }
  // STORE u otros sin el cuerpo completo: solo tenemos el check byte.
  return true;
}

// Decrypt (and inflate if needed) with a known-correct password.
function decrypt(entry, password, encoding = 'utf8') {
  const raw = decryptBody(entry, password, encoding);
  return entry.method === 8 ? zlib.inflateRawSync(raw) : raw;
}

// Decrypt the body using recovered internal keys (no password needed). The keys
// are the state right after password initialisation and before the 12-byte
// header, so we consume the header first to advance the state.
function decryptBodyWithKeys(entry, [k0, k1, k2]) {
  const keys = Keys.fromState(k0, k1, k2);
  const header = entry.header;
  for (let i = 0; i < 12; i++) keys.decryptByte(header[i]);
  const body = entry.body;
  const out = Buffer.allocUnsafe(body.length);
  for (let i = 0; i < body.length; i++) out[i] = keys.decryptByte(body[i]);
  return out;
}

// Decrypt (and inflate) an entry from recovered internal keys.
function decryptWithKeys(entry, state) {
  const raw = decryptBodyWithKeys(entry, state);
  return entry.method === 8 ? zlib.inflateRawSync(raw) : raw;
}

module.exports = {
  crc32,
  crc32Byte,
  crc32InvByte,
  CRC_TABLE,
  CRC_INV_TABLE,
  MULT,
  MULTINV,
  Keys,
  expectedCheckByte,
  checkByteMatches,
  decryptBody,
  verifyPassword,
  verifyPasswordPrefix,
  decrypt,
  decryptBodyWithKeys,
  decryptWithKeys,
};
