'use strict';

// "Sonda" (probe): paquete compacto para atacar un ZIP cifrado grande sin mover
// el archivo entero. Sirve para dos cosas, ambas sobre unos pocos KB:
//   - ataque de texto plano (ZipCrypto): cabecera de cifrado (12 B) + prefijo
//     del cuerpo cifrado -> recupera las claves internas.
//   - recuperación de la contraseña (ZipCrypto y WinZip AES): el material de
//     verificación (header+CRC / salt+verificador) + un prefijo del cuerpo.
//
// Con las claves o la contraseña, se descifra TODO el archivo en la máquina que
// sí lo tiene. Un zip de varios GB se ataca compartiendo apenas unos KB.

const path = require('path');

const zc = require('./crypto-zipcrypto');
const aes = require('./crypto-aes');

const PROBE_VERSION = 1;
const DEFAULT_SLICE = 4096;

function sliceLen(bytes) {
  return Math.max(0, Number.isFinite(bytes) ? bytes : DEFAULT_SLICE);
}

// Construye la sonda de una entrada cifrada (ZipCrypto o AES) de un zip leído.
function buildProbe(zip, entry, { bytes = DEFAULT_SLICE } = {}) {
  if (entry.encryption !== 'zipcrypto' && entry.encryption !== 'aes') {
    throw new Error(`la sonda es para entradas cifradas; "${entry.name}" no lo está`);
  }
  const probe = {
    sonda: PROBE_VERSION,
    archivo: path.basename(zip.path),
    entrada: {
      indice: entry.index,
      nombre: entry.name,
      metodo: entry.method,
      cifrado: entry.encryption,
      comprimido: entry.compressedSize,
      original: entry.uncompressedSize,
      crc: entry.crc >>> 0,
      flags: (entry.flags ?? 0) >>> 0,
      mtime: (entry.mtime ?? 0) >>> 0,
    },
  };

  if (entry.encryption === 'zipcrypto') {
    const slice = entry.crypto.body.subarray(0, sliceLen(bytes));
    probe.cabecera_hex = Buffer.from(entry.crypto.header).toString('hex');
    probe.cuerpo_prefijo_hex = slice.toString('hex');
    probe.cuerpo_prefijo_bytes = slice.length;
    probe.cuerpo_completo = slice.length >= entry.crypto.body.length;
  } else {
    const slice = entry.crypto.ciphertext.subarray(0, sliceLen(bytes));
    probe.aes = {
      strength: entry.crypto.strength,
      version: entry.aes ? entry.aes.version : undefined,
      salt_hex: Buffer.from(entry.crypto.salt).toString('hex'),
      verify_hex: Buffer.from(entry.crypto.verify).toString('hex'),
      auth_hex: Buffer.from(entry.crypto.auth).toString('hex'),
    };
    probe.cuerpo_prefijo_hex = slice.toString('hex');
    probe.cuerpo_prefijo_bytes = slice.length;
    probe.cuerpo_completo = slice.length >= entry.crypto.ciphertext.length;
  }
  return probe;
}

// Reconstruye desde una sonda una entrada mínima (con su objeto `crypto`) y el
// ciphertext disponible. Devuelve { entry, ciphertext, archivo, cuerpoCompleto }.
function fromProbe(probe) {
  if (!probe || probe.sonda !== PROBE_VERSION) {
    throw new Error('sonda no reconocida (falta el campo "sonda" o versión distinta)');
  }
  const e = probe.entrada || {};
  const body = Buffer.from(String(probe.cuerpo_prefijo_hex || ''), 'hex');
  const common = {
    index: e.indice ?? 0,
    name: e.nombre || 'entrada',
    method: e.metodo ?? 0,
    encryption: e.cifrado,
    crc: (e.crc ?? 0) >>> 0,
    flags: (e.flags ?? 0) >>> 0,
    mtime: (e.mtime ?? 0) >>> 0,
    compressedSize: e.comprimido ?? body.length,
    uncompressedSize: e.original ?? 0,
  };

  if (e.cifrado === 'zipcrypto') {
    const header = Buffer.from(String(probe.cabecera_hex || ''), 'hex');
    if (header.length !== 12) throw new Error('sonda inválida: la cabecera debe ser de 12 bytes');
    if (body.length === 0) throw new Error('sonda inválida: el prefijo del cuerpo está vacío');
    const crypto = { method: common.method, flags: common.flags, crc: common.crc, mtime: common.mtime, header, body };
    return {
      entry: { ...common, crypto },
      ciphertext: Buffer.concat([header, body]),
      archivo: probe.archivo,
      cuerpoCompleto: !!probe.cuerpo_completo,
    };
  }
  if (e.cifrado === 'aes') {
    const a = probe.aes || {};
    const crypto = {
      strength: a.strength,
      salt: Buffer.from(String(a.salt_hex || ''), 'hex'),
      verify: Buffer.from(String(a.verify_hex || ''), 'hex'),
      ciphertext: body,
      auth: Buffer.from(String(a.auth_hex || ''), 'hex'),
    };
    if (crypto.salt.length === 0 || crypto.verify.length !== 2) {
      throw new Error('sonda AES inválida (falta salt o verificador)');
    }
    return {
      entry: { ...common, crypto },
      ciphertext: body,
      archivo: probe.archivo,
      cuerpoCompleto: !!probe.cuerpo_completo,
    };
  }
  throw new Error(`sonda con cifrado no soportado: ${e.cifrado}`);
}

// Verifica una contraseña candidata contra lo que trae la sonda:
//   AES       -> verificador de 2 bytes (PBKDF2); 1/65536, definitivo en origen.
//   ZipCrypto -> check byte + validación del prefijo (CRC si el cuerpo es
//                completo; inflate/magia si es parcial).
function verifyFromProbe(reco, password, { encoding = 'utf8' } = {}) {
  const { entry, cuerpoCompleto } = reco;
  if (entry.encryption === 'aes') {
    return aes.verifyPassword(entry.crypto, password, { fast: true, encoding });
  }
  if (entry.encryption === 'zipcrypto') {
    return zc.verifyPasswordPrefix(entry.crypto, password, { encoding, full: cuerpoCompleto });
  }
  return false;
}

module.exports = { buildProbe, fromProbe, verifyFromProbe, PROBE_VERSION, DEFAULT_SLICE };
