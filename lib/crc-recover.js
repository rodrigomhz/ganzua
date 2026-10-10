'use strict';

// Recuperación de contenido por CRC-32 SIN descifrar nada.
//
// El directorio central de un ZIP guarda el CRC-32 del contenido EN CLARO de
// cada entrada, aunque la entrada esté cifrada. ZipCrypto lo almacena siempre;
// WinZip AES solo en su variante AE-1 (AE-2 guarda CRC=0). Para entradas
// pequeñas ese CRC basta para reconstruir el contenido por fuerza bruta del
// texto plano, sin tocar la contraseña ni el flujo cifrado.
//
// Unicidad: el CRC-32 sobre una entrada de longitud fija ≤ 4 bytes (≤ 32 bits)
// es inyectivo, así que para tamaños de 1 a 4 bytes el contenido recuperado es
// EL contenido (no hay ambigüedad). A partir de 5 bytes puede haber colisiones
// y se devuelve la primera coincidencia.

const { crc32 } = require('./crypto-zipcrypto');

// Presets de alfabeto para restringir la búsqueda (charset^tamaño).
const CHARSETS = {
  digits: '0123456789',
  lower: 'abcdefghijklmnopqrstuvwxyz',
  upper: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
  alnum: '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ',
  hex: '0123456789abcdef',
  // ASCII imprimible (espacio incluido): 0x20..0x7e.
  print: Array.from({ length: 0x7e - 0x20 + 1 }, (_, i) => String.fromCharCode(0x20 + i)).join(''),
};

// ~16.7M combinaciones (≈1-2 s en JS): permite hasta 3 bytes con los 256
// valores, o tamaños mayores con un alfabeto restringido.
const DEFAULT_MAX_SPACE = 1 << 24;

// Traduce `spec` (nombre de preset, o literal de caracteres, o "bytes"/"all"
// para los 256 valores) a un Uint8Array de bytes candidatos, sin duplicados.
function charsetBytes(spec) {
  if (spec == null || spec === 'bytes' || spec === 'all') {
    const a = new Uint8Array(256);
    for (let i = 0; i < 256; i++) a[i] = i;
    return a;
  }
  const src = Object.prototype.hasOwnProperty.call(CHARSETS, spec) ? CHARSETS[spec] : spec;
  const seen = new Uint8Array(256);
  const out = [];
  for (const b of Buffer.from(String(src), 'latin1')) {
    if (!seen[b]) {
      seen[b] = 1;
      out.push(b);
    }
  }
  return Uint8Array.from(out);
}

// Tamaño del espacio de búsqueda (charset^size) como número (puede ser Infinity).
function searchSpace(alphabetSize, size) {
  return Math.pow(alphabetSize, size);
}

function formatSpace(n) {
  if (!Number.isFinite(n)) return '∞';
  if (n >= 1e9) return `${(n / 1e9).toFixed(1)}·10⁹`;
  if (n >= 1e6) return `${(n / 1e6).toFixed(1)}·10⁶`;
  return String(n);
}

// ¿El CRC-32 de la entrada está en claro en los metadatos? ZipCrypto y las
// entradas sin cifrar siempre; WinZip AES solo en AE-1.
function crcLeaked(entry) {
  if (entry.encryption === 'none' || entry.encryption === 'zipcrypto') return true;
  if (entry.encryption === 'aes') return !!(entry.aes && entry.aes.version === 1);
  return false;
}

// Recupera el contenido de `size` bytes cuyo CRC-32 es `targetCrc`, probando
// todas las combinaciones del alfabeto. Devuelve un Buffer, o null si ninguna
// combinación casa. Lanza (code SPACE_TOO_LARGE) si el espacio supera maxSpace.
//   opts.charset     nombre de preset o literal (por defecto, los 256 valores)
//   opts.charsetBytes Uint8Array ya resuelto (tiene prioridad sobre charset)
//   opts.maxSpace    límite de combinaciones (por defecto ~16.7M)
//   opts.onProgress  (hechas, total) => void, llamado periódicamente
function recoverByCrc(targetCrc, size, opts = {}) {
  const target = targetCrc >>> 0;
  if (!Number.isInteger(size) || size < 0) throw new Error('tamaño inválido');
  // Una entrada de 0 bytes tiene contenido vacío y CRC-32 = 0.
  if (size === 0) return target === 0 ? Buffer.alloc(0) : null;

  const charset = opts.charsetBytes || charsetBytes(opts.charset);
  if (charset.length === 0) throw new Error('alfabeto vacío');
  const maxSpace = opts.maxSpace == null ? DEFAULT_MAX_SPACE : opts.maxSpace;
  const space = searchSpace(charset.length, size);
  if (!Number.isFinite(space) || space > maxSpace) {
    const err = new Error(
      `espacio de búsqueda demasiado grande (${formatSpace(space)} combinaciones): ` +
        'restringe el alfabeto (--charset) o baja el tamaño máximo (--maxbytes)',
    );
    err.code = 'SPACE_TOO_LARGE';
    err.space = space;
    throw err;
  }

  const buf = Buffer.alloc(size);
  const idx = new Uint32Array(size); // contador en base variable (todos a 0)
  const R = charset.length;
  const onProgress = opts.onProgress;
  for (let n = 0; ; n++) {
    for (let j = 0; j < size; j++) buf[j] = charset[idx[j]];
    if (crc32(buf) === target) return Buffer.from(buf);
    // Incrementa el contador de dígitos mixtos (posición menos significativa
    // = último byte). Si desborda todas las posiciones, se agotó el espacio.
    let k = size - 1;
    for (; k >= 0; k--) {
      if (++idx[k] < R) break;
      idx[k] = 0;
    }
    if (k < 0) break;
    if (onProgress && (n & 0x3fffff) === 0) onProgress(n, space);
  }
  return null;
}

module.exports = {
  CHARSETS,
  DEFAULT_MAX_SPACE,
  charsetBytes,
  searchSpace,
  formatSpace,
  crcLeaked,
  recoverByCrc,
};
