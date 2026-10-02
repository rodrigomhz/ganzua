'use strict';

// Detección de formato de archivo por firma (magic bytes) y guía de ataque.
// ganzua ataca ZIP de forma nativa; para 7-Zip y RAR indica la vía establecida
// (modo de hashcat + herramienta *2john), ya que esos formatos requieren un
// parser propio que queda fuera del alcance nativo.

const fs = require('fs');

// Firmas ordenadas de más específica a menos (RAR5 antes que RAR4).
const SIGNATURES = [
  { magic: [0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c], id: '7z' },
  { magic: [0x52, 0x61, 0x72, 0x21, 0x1a, 0x07, 0x01, 0x00], id: 'rar5' },
  { magic: [0x52, 0x61, 0x72, 0x21, 0x1a, 0x07, 0x00], id: 'rar4' },
  { magic: [0x50, 0x4b, 0x03, 0x04], id: 'zip' },
  { magic: [0x50, 0x4b, 0x05, 0x06], id: 'zip' }, // ZIP vacío
  { magic: [0x50, 0x4b, 0x07, 0x08], id: 'zip' }, // ZIP spanned
  { magic: [0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00], id: 'xz' },
  { magic: [0x1f, 0x8b], id: 'gzip' },
  { magic: [0x42, 0x5a, 0x68], id: 'bzip2' },
];

// Descripción y vía de ataque por formato.
const INFO = {
  zip: {
    nombre: 'ZIP',
    nativo: true,
    guia: 'ganzua lo ataca de forma nativa: romper / extrae / textoplano.',
  },
  '7z': {
    nombre: '7-Zip',
    nativo: false,
    guia:
      '7-Zip (AES-256). Extrae el hash y crackea con hashcat modo 11600:\n' +
      '  7z2john archivo.7z > hash.txt && hashcat -m 11600 hash.txt wordlist.txt',
  },
  rar5: {
    nombre: 'RAR5',
    nativo: false,
    guia:
      'RAR5 (AES-256). hashcat modo 13000:\n' +
      '  rar2john archivo.rar > hash.txt && hashcat -m 13000 hash.txt wordlist.txt',
  },
  rar4: {
    nombre: 'RAR3/RAR4',
    nativo: false,
    guia:
      'RAR3 (-hp, AES-128). hashcat modo 12500:\n' +
      '  rar2john archivo.rar > hash.txt && hashcat -m 12500 hash.txt wordlist.txt',
  },
  gzip: { nombre: 'gzip', nativo: false, guia: 'gzip solo comprime; no tiene cifrado con contraseña.' },
  bzip2: { nombre: 'bzip2', nativo: false, guia: 'bzip2 solo comprime; no tiene cifrado con contraseña.' },
  xz: { nombre: 'xz', nativo: false, guia: 'xz solo comprime; no tiene cifrado con contraseña.' },
  desconocido: { nombre: 'desconocido', nativo: false, guia: 'firma no reconocida.' },
};

function startsWith(buf, magic) {
  if (buf.length < magic.length) return false;
  for (let i = 0; i < magic.length; i++) if (buf[i] !== magic[i]) return false;
  return true;
}

// Detecta el formato a partir de los primeros bytes.
function detectFormat(buf) {
  for (const sig of SIGNATURES) if (startsWith(buf, sig.magic)) return sig.id;
  return 'desconocido';
}

// Detecta el formato de un fichero (lee solo la cabecera).
function detectFile(path) {
  const fd = fs.openSync(path, 'r');
  try {
    const head = Buffer.alloc(16);
    const n = fs.readSync(fd, head, 0, 16, 0);
    return detectFormat(head.subarray(0, n));
  } finally {
    fs.closeSync(fd);
  }
}

function info(id) {
  return INFO[id] || INFO.desconocido;
}

module.exports = { detectFormat, detectFile, info, SIGNATURES, INFO };
