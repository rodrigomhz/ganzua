'use strict';

// Minimal ZIP container parser focused on what a password-recovery tool needs:
// locate entries, detect the encryption scheme, and slice out the crypto
// material. The central directory is the authoritative source of sizes/flags
// (reliable even when a data descriptor zeroes the local header fields); local
// headers are used only to locate where each entry's data actually begins.

const fs = require('fs');
const { decodeZipName } = require('./encoding');

const SIG_LOCAL = 0x04034b50;
const SIG_CENTRAL = 0x02014b50;
const SIG_EOCD = 0x06054b50;
const SIG_EOCD64 = 0x06064b50;
const SIG_EOCD64_LOC = 0x07064b50;

const AES_METHOD = 99;
const AES_EXTRA_ID = 0x9901;
const ZIP64_EXTRA_ID = 0x0001;
const UNICODE_PATH_EXTRA_ID = 0x7075;
const AES_SALT_LEN = { 1: 8, 2: 12, 3: 16 };
const AES_AUTH_LEN = 10;
const AES_VERIFY_LEN = 2;

class ZipError extends Error {}

// Scan backwards for the End Of Central Directory record.
function findEOCD(buf) {
  const minLen = 22;
  if (buf.length < minLen) throw new ZipError('archivo demasiado corto para ser un ZIP');
  const maxComment = 0xffff;
  const start = Math.max(0, buf.length - minLen - maxComment);
  for (let i = buf.length - minLen; i >= start; i--) {
    if (buf.readUInt32LE(i) === SIG_EOCD) return i;
  }
  throw new ZipError('no se encontró el registro EOCD (¿no es un ZIP?)');
}

function parseAesExtra(extra) {
  let off = 0;
  while (off + 4 <= extra.length) {
    const id = extra.readUInt16LE(off);
    const size = extra.readUInt16LE(off + 2);
    const body = extra.subarray(off + 4, off + 4 + size);
    if (id === AES_EXTRA_ID && body.length >= 7) {
      return {
        version: body.readUInt16LE(0), // 1 = AE-1, 2 = AE-2
        vendor: body.subarray(2, 4).toString('latin1'),
        strength: body.readUInt8(4), // 1/2/3 => 128/192/256
        actualMethod: body.readUInt16LE(5),
      };
    }
    off += 4 + size;
  }
  return null;
}

// Info-ZIP Unicode Path extra field (0x7075): version(1) + nameCRC32(4) +
// UTF-8 name. When present it holds the authoritative UTF-8 filename.
function parseUnicodePathExtra(extra) {
  let off = 0;
  while (off + 4 <= extra.length) {
    const id = extra.readUInt16LE(off);
    const size = extra.readUInt16LE(off + 2);
    if (id === UNICODE_PATH_EXTRA_ID && size >= 5) {
      const version = extra.readUInt8(off + 4);
      if (version === 1) return extra.subarray(off + 9, off + 4 + size).toString('utf8');
    }
    off += 4 + size;
  }
  return null;
}

// Compute where an entry's file data starts by reading its local header.
function localDataOffset(buf, localOffset) {
  if (buf.readUInt32LE(localOffset) !== SIG_LOCAL) {
    throw new ZipError(`cabecera local inválida en offset ${localOffset}`);
  }
  const fnLen = buf.readUInt16LE(localOffset + 26);
  const efLen = buf.readUInt16LE(localOffset + 28);
  return localOffset + 30 + fnLen + efLen;
}

function detectEncryption(method, flags) {
  if (method === AES_METHOD) return 'aes';
  if (flags & 0x1) return 'zipcrypto';
  return 'none';
}

// Métodos de compresión que ganzua puede descomprimir.
const DECOMPRESSIBLE = new Set([0, 8, 12, 14]); // STORE, DEFLATE, BZIP2, LZMA

const METHOD_NAMES = { 0: 'STORE', 8: 'DEFLATE', 9: 'DEFLATE64', 12: 'BZIP2', 14: 'LZMA', 95: 'XZ', 98: 'PPMd' };

function methodName(m) {
  return METHOD_NAMES[m] || `método ${m}`;
}

// Parse the ZIP64 extended information extra field (0x0001). The 8-byte values
// appear only for the base fields set to 0xffffffff (0xffff for disk), in this
// order: uncompressed size, compressed size, local header offset, disk start.
function parseZip64Extra(extra, needs) {
  let off = 0;
  while (off + 4 <= extra.length) {
    const id = extra.readUInt16LE(off);
    const size = extra.readUInt16LE(off + 2);
    if (id === ZIP64_EXTRA_ID) {
      const body = extra.subarray(off + 4, off + 4 + size);
      const out = {};
      let p = 0;
      if (needs.usize && p + 8 <= body.length) {
        out.uncompressedSize = Number(body.readBigUInt64LE(p));
        p += 8;
      }
      if (needs.csize && p + 8 <= body.length) {
        out.compressedSize = Number(body.readBigUInt64LE(p));
        p += 8;
      }
      if (needs.offset && p + 8 <= body.length) {
        out.localOffset = Number(body.readBigUInt64LE(p));
        p += 8;
      }
      if (needs.disk && p + 4 <= body.length) {
        out.diskStart = body.readUInt32LE(p);
      }
      return out;
    }
    off += 4 + size;
  }
  return {};
}

// Build the per-entry crypto material used by the verifiers.
function buildCrypto(entry, buf) {
  const dataStart = entry.dataOffset;
  const data = buf.subarray(dataStart, dataStart + entry.compressedSize);

  if (entry.encryption === 'aes') {
    const saltLen = AES_SALT_LEN[entry.aes.strength];
    if (!saltLen) throw new ZipError(`fuerza AES desconocida (${entry.aes.strength})`);
    const ctLen = data.length - saltLen - AES_VERIFY_LEN - AES_AUTH_LEN;
    if (ctLen < 0) throw new ZipError('datos AES truncados');
    return {
      strength: entry.aes.strength,
      salt: data.subarray(0, saltLen),
      verify: data.subarray(saltLen, saltLen + AES_VERIFY_LEN),
      ciphertext: data.subarray(saltLen + AES_VERIFY_LEN, saltLen + AES_VERIFY_LEN + ctLen),
      auth: data.subarray(data.length - AES_AUTH_LEN),
    };
  }

  if (entry.encryption === 'zipcrypto') {
    if (data.length < 12) throw new ZipError('cabecera ZipCrypto truncada');
    return {
      method: entry.method,
      flags: entry.flags,
      crc: entry.crc,
      mtime: entry.mtime,
      header: data.subarray(0, 12),
      body: data.subarray(12),
    };
  }

  return null;
}

// Parse the central directory into entry descriptors.
function parseCentralDirectory(buf) {
  const eocd = findEOCD(buf);
  const totalEntries = buf.readUInt16LE(eocd + 10);
  const cdSize = buf.readUInt32LE(eocd + 12);
  let cdOffset = buf.readUInt32LE(eocd + 16);

  const zip64 =
    buf.readUInt16LE(eocd + 4) === 0xffff ||
    cdOffset === 0xffffffff ||
    (eocd >= 20 && buf.readUInt32LE(eocd - 20) === SIG_EOCD64_LOC);
  if (zip64) {
    const locOff = eocd - 20;
    if (locOff >= 0 && buf.readUInt32LE(locOff) === SIG_EOCD64_LOC) {
      const eocd64 = Number(buf.readBigUInt64LE(locOff + 8));
      if (buf.readUInt32LE(eocd64) === SIG_EOCD64) {
        cdOffset = Number(buf.readBigUInt64LE(eocd64 + 48));
      }
    }
  }

  // Ajuste para datos antepuestos (stubs SFX .exe): el directorio central
  // termina justo donde empieza el EOCD, así que su inicio real es eocd-cdSize.
  // Si difiere del offset declarado, hay N bytes antepuestos: se aplica ese
  // delta al offset del CD y a los offsets locales de cada entrada.
  let baseOffset = 0;
  if (!zip64 && cdSize !== 0xffffffff) {
    const realCdStart = eocd - cdSize;
    if (realCdStart >= 0 && realCdStart !== cdOffset && buf.readUInt32LE(realCdStart) === SIG_CENTRAL) {
      baseOffset = realCdStart - cdOffset;
      cdOffset = realCdStart;
    }
  }

  const entries = [];
  let off = cdOffset;
  for (let i = 0; i < totalEntries; i++) {
    if (off + 46 > buf.length || buf.readUInt32LE(off) !== SIG_CENTRAL) break;
    const flags = buf.readUInt16LE(off + 8);
    const method = buf.readUInt16LE(off + 10);
    const mtime = buf.readUInt16LE(off + 12);
    const crc = buf.readUInt32LE(off + 16);
    let compressedSize = buf.readUInt32LE(off + 20);
    let uncompressedSize = buf.readUInt32LE(off + 24);
    const fnLen = buf.readUInt16LE(off + 28);
    const efLen = buf.readUInt16LE(off + 30);
    const commentLen = buf.readUInt16LE(off + 32);
    const diskStart = buf.readUInt16LE(off + 34);
    let localOffset = buf.readUInt32LE(off + 42) + baseOffset;
    const nameRaw = buf.subarray(off + 46, off + 46 + fnLen);
    const extra = buf.subarray(off + 46 + fnLen, off + 46 + fnLen + efLen);
    // Nombre: EFS (bit 11) => UTF-8; si no, CP437. El campo extra 0x7075
    // (Unicode Path) tiene prioridad cuando está presente.
    const name = parseUnicodePathExtra(extra) || decodeZipName(nameRaw, flags);

    // ZIP64: pull the real 64-bit sizes/offset from the 0x0001 extra field for
    // any base field that overflowed to its sentinel value.
    const needs = {
      usize: uncompressedSize === 0xffffffff,
      csize: compressedSize === 0xffffffff,
      offset: localOffset === 0xffffffff,
      disk: diskStart === 0xffff,
    };
    if (needs.usize || needs.csize || needs.offset || needs.disk) {
      const z64 = parseZip64Extra(extra, needs);
      if (z64.uncompressedSize !== undefined) uncompressedSize = z64.uncompressedSize;
      if (z64.compressedSize !== undefined) compressedSize = z64.compressedSize;
      if (z64.localOffset !== undefined) localOffset = z64.localOffset;
    }

    const encryption = detectEncryption(method, flags);
    let realMethod = method;
    let aes = null;
    if (encryption === 'aes') {
      aes = parseAesExtra(extra);
      if (aes) realMethod = aes.actualMethod;
    }

    entries.push({
      index: i,
      name,
      flags,
      method: realMethod,
      rawMethod: method,
      crc,
      mtime,
      compressedSize,
      uncompressedSize,
      localOffset,
      encryption,
      aes,
    });

    off += 46 + fnLen + efLen + commentLen;
  }

  return { entries, zip64 };
}

// Read and fully parse a ZIP file, attaching crypto material to each entry.
function readZip(path) {
  const buf = fs.readFileSync(path);
  const { entries, zip64 } = parseCentralDirectory(buf);
  for (const entry of entries) {
    entry.dataOffset = localDataOffset(buf, entry.localOffset);
    entry.crypto = buildCrypto(entry, buf);
  }
  return { path, buf, entries, zip64 };
}

// Pick the first encrypted entry (the default target for cracking/analysis).
function firstEncryptedEntry(zip) {
  return zip.entries.find((e) => e.encryption !== 'none') || null;
}

module.exports = {
  ZipError,
  AES_SALT_LEN,
  readZip,
  parseCentralDirectory,
  findEOCD,
  parseAesExtra,
  parseZip64Extra,
  detectEncryption,
  firstEncryptedEntry,
  methodName,
  DECOMPRESSIBLE,
};
