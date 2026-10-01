'use strict';

// "Sonda" (probe): paquete compacto para atacar un ZipCrypto grande sin mover
// el archivo entero. El ataque de texto plano de Biham-Kocher solo necesita la
// cabecera de cifrado (12 bytes) y un prefijo del cuerpo cifrado; con eso se
// recuperan las claves internas, que luego descifran TODO el archivo en la
// máquina que sí tiene el zip completo.
//
// Así, un zip de varios GB se ataca compartiendo apenas unos KB (la sonda).

const path = require('path');

const PROBE_VERSION = 1;
const DEFAULT_SLICE = 4096;

// Construye la sonda de una entrada ZipCrypto de un zip ya leído (readZip).
function buildProbe(zip, entry, { bytes = DEFAULT_SLICE } = {}) {
  if (entry.encryption !== 'zipcrypto') {
    throw new Error(`la sonda de texto plano es para ZipCrypto; "${entry.name}" es ${entry.encryption}`);
  }
  const n = Math.max(0, Number.isFinite(bytes) ? bytes : DEFAULT_SLICE);
  const slice = entry.crypto.body.subarray(0, n);
  return {
    sonda: PROBE_VERSION,
    archivo: path.basename(zip.path),
    entrada: {
      indice: entry.index,
      nombre: entry.name,
      metodo: entry.method,
      cifrado: 'zipcrypto',
      comprimido: entry.compressedSize,
      original: entry.uncompressedSize,
      crc: entry.crc >>> 0,
    },
    // Cabecera de cifrado (12 B) + prefijo del cuerpo cifrado, en hex.
    cabecera_hex: Buffer.from(entry.crypto.header).toString('hex'),
    cuerpo_prefijo_hex: Buffer.from(slice).toString('hex'),
    cuerpo_prefijo_bytes: slice.length,
  };
}

// Reconstruye desde una sonda lo necesario para el ataque: una entrada mínima
// (nombre/método/tamaños, para elegir texto plano) y el ciphertext disponible
// (cabecera + prefijo del cuerpo).
function fromProbe(probe) {
  if (!probe || probe.sonda !== PROBE_VERSION) {
    throw new Error('sonda no reconocida (falta el campo "sonda" o versión distinta)');
  }
  const e = probe.entrada || {};
  const header = Buffer.from(String(probe.cabecera_hex || ''), 'hex');
  const body = Buffer.from(String(probe.cuerpo_prefijo_hex || ''), 'hex');
  if (header.length !== 12) throw new Error('sonda inválida: la cabecera debe ser de 12 bytes');
  if (body.length === 0) throw new Error('sonda inválida: el prefijo del cuerpo está vacío');
  const entry = {
    index: e.indice ?? 0,
    name: e.nombre || 'entrada',
    method: e.metodo ?? 0,
    encryption: 'zipcrypto',
    compressedSize: e.comprimido ?? body.length,
    uncompressedSize: e.original ?? 0,
    crc: (e.crc ?? 0) >>> 0,
  };
  return { entry, ciphertext: Buffer.concat([header, body]), archivo: probe.archivo };
}

module.exports = { buildProbe, fromProbe, PROBE_VERSION, DEFAULT_SLICE };
