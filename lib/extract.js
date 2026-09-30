'use strict';

// Extracción del contenido: descifra (AES o ZipCrypto) y descomprime cada
// entrada, verificando el CRC-32, y la escribe en disco de forma segura
// (protección contra "zip slip" / path traversal).

const fs = require('fs');
const path = require('path');
const zlib = require('zlib');

const { decrypt } = require('./verify');
const { crc32 } = require('./crypto-zipcrypto');

// Devuelve el contenido en claro (descomprimido) de una entrada.
//   - sin cifrar: lee del buffer y descomprime si es DEFLATE.
//   - cifrada:    delega en verify.decrypt (que ya descomprime).
function plaintext(entry, zip, password) {
  if (entry.encryption === 'none') {
    const raw = zip.buf.subarray(entry.dataOffset, entry.dataOffset + entry.compressedSize);
    return entry.method === 8 ? zlib.inflateRawSync(raw) : Buffer.from(raw);
  }
  return decrypt(entry, password);
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
function extractEntries(zip, entries, { password, outDir, onFile } = {}) {
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
      const plain = plaintext(entry, zip, password);
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
