'use strict';

// Extracción del contenido: descifra (AES o ZipCrypto) y descomprime cada
// entrada, verificando el CRC-32, y la escribe en disco de forma segura
// (protección contra "zip slip" / path traversal).

const fs = require('fs');
const path = require('path');

const aes = require('./crypto-aes');
const zc = require('./crypto-zipcrypto');
const { crc32 } = zc;
const { decompress } = require('./decompress');

// Devuelve el flujo (aún comprimido) de una entrada, ya descifrado.
function rawStream(entry, zip, { password, keys, encoding = 'utf8' }) {
  if (entry.encryption === 'none') {
    return zip.buf.subarray(entry.dataOffset, entry.dataOffset + entry.compressedSize);
  }
  if (entry.encryption === 'zipcrypto') {
    return keys ? zc.decryptBodyWithKeys(entry.crypto, keys) : zc.decryptBody(entry.crypto, password, encoding);
  }
  if (entry.encryption === 'aes') {
    return aes.decrypt(entry.crypto, password, encoding);
  }
  throw new Error(`entrada "${entry.name}" con cifrado desconocido`);
}

// Devuelve el contenido en claro (descifrado + descomprimido) de una entrada.
async function plaintext(entry, zip, opts = {}) {
  const comp = rawStream(entry, zip, opts);
  return decompress(entry.method, comp, entry.uncompressedSize);
}

// Comprueba el CRC-32 del contenido en claro contra el del directorio central.
// (En AE-2 el CRC almacenado es 0 y no se puede comparar; ahí confiamos en el
// HMAC que ya validó la contraseña.)
function crcOk(entry, plain) {
  if (entry.crc === 0) return true; // AE-2 (o entrada sin CRC): no comparable
  return crc32(plain) === entry.crc >>> 0;
}

// Normaliza el nombre de una entrada a una ruta segura dentro de baseDir.
// Rechaza rutas absolutas y componentes ".." (zip slip).
function safeJoin(baseDir, entryName) {
  const normalized = entryName.replace(/\\/g, '/');
  const parts = [];
  for (const part of normalized.split('/')) {
    if (part === '' || part === '.') continue;
    if (part === '..') throw new Error(`ruta insegura en la entrada: "${entryName}"`);
    parts.push(part);
  }
  if (parts.length === 0) throw new Error(`nombre de entrada vacío: "${entryName}"`);
  const target = path.join(baseDir, ...parts);
  const rel = path.relative(baseDir, target);
  if (rel.startsWith('..') || path.isAbsolute(rel)) {
    throw new Error(`ruta insegura en la entrada: "${entryName}"`);
  }
  return target;
}

// Extrae las entradas indicadas a outDir. Devuelve un informe por entrada.
//   entries: lista de entradas a extraer (ya resueltas por el llamador)
//   password: contraseña (ignorada por las entradas sin cifrar)
//   keys: claves internas ZipCrypto recuperadas (alternativa a password)
async function extractEntries(zip, entries, { password, keys, outDir, onFile, encoding = 'utf8' } = {}) {
  const results = [];
  for (const entry of entries) {
    const isDir = entry.name.endsWith('/');
    let dest;
    try {
      dest = safeJoin(outDir, entry.name);
    } catch (err) {
      results.push({ nombre: entry.name, ok: false, error: err.message });
      continue;
    }

    if (isDir) {
      fs.mkdirSync(dest, { recursive: true });
      results.push({ nombre: entry.name, ruta: dest, ok: true, directorio: true });
      continue;
    }

    try {
      const plain = await plaintext(entry, zip, { password, keys, encoding });
      if (!crcOk(entry, plain)) {
        results.push({ nombre: entry.name, ok: false, error: 'CRC no coincide (¿contraseña incorrecta?)' });
        continue;
      }
      fs.mkdirSync(path.dirname(dest), { recursive: true });
      fs.writeFileSync(dest, plain);
      results.push({ nombre: entry.name, ruta: dest, ok: true, bytes: plain.length });
      if (onFile) onFile(entry.name, dest, plain.length);
    } catch (err) {
      results.push({ nombre: entry.name, ok: false, error: err.message });
    }
  }
  return results;
}

module.exports = { plaintext, crcOk, safeJoin, extractEntries };
