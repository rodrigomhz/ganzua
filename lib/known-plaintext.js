'use strict';

// Catálogo de texto plano conocido por tipo de fichero (#1). Muchos formatos
// —en especial los de máquinas virtuales— empiezan por cabeceras fijas. Para
// una entrada ZipCrypto guardada SIN comprimir (STORE), esa cabecera es texto
// plano del flujo cifrado en un offset conocido: basta para el ataque de
// Biham-Kocher (≥12 bytes) sin tener que dar el texto plano a mano.
//
// Ojo: estas firmas son del contenido EN CLARO. Solo sirven directamente para
// entradas STORE (método 0). Para entradas DEFLATE hay que recomprimir un
// fichero conocido (ver lib/deflate-plain.js).

const { ATTACK_SIZE } = require('./zipcrypto-attack');

// b(): bytes desde hex o desde texto latin1.
function b(spec, hex) {
  return hex ? Buffer.from(spec, 'hex') : Buffer.from(spec, 'latin1');
}

// Cada firma: { id, etiqueta, exts, offset, bytes }. `offset` es la posición
// (dentro del contenido en claro) donde aparecen esos bytes.
const SIGNATURES = [
  // --- Máquinas virtuales ---------------------------------------------------
  {
    id: 'ovf-xml',
    etiqueta: 'OVF/XML (<?xml …)',
    exts: ['ovf', 'xml', 'vbox'],
    offset: 0,
    bytes: b('<?xml version="1.0"'),
  },
  {
    id: 'ova-ovf',
    etiqueta: 'OVA (TAR → OVF en offset 512)',
    exts: ['ova'],
    offset: 512,
    bytes: b('<?xml version="1.0"'),
  },
  {
    id: 'vmdk-desc',
    etiqueta: 'VMDK (descriptor de texto)',
    exts: ['vmdk'],
    offset: 0,
    bytes: b('# Disk DescriptorFile'),
  },
  {
    id: 'vmdk-sparse',
    etiqueta: 'VMDK (sparse «KDMV»)',
    exts: ['vmdk'],
    offset: 0,
    bytes: b('4b444d5601000000030000000000', true),
  },
  {
    id: 'vdi',
    etiqueta: 'VirtualBox VDI',
    exts: ['vdi'],
    offset: 0,
    bytes: b('<<< Oracle VM VirtualBox Disk Image >>>'),
  },
  {
    id: 'vhd',
    etiqueta: 'VHD (footer «conectix»)',
    exts: ['vhd'],
    offset: 0,
    bytes: b('636f6e6563746978000000020001000000', true),
  },
  {
    id: 'qcow2-v3',
    etiqueta: 'QEMU QCOW2 (v3)',
    exts: ['qcow2', 'qcow'],
    offset: 0,
    bytes: b('514649fb0000000300000000', true),
  },
  {
    id: 'qcow2-v2',
    etiqueta: 'QEMU QCOW2 (v2)',
    exts: ['qcow2', 'qcow'],
    offset: 0,
    bytes: b('514649fb0000000200000000', true),
  },
  { id: 'vmx', etiqueta: 'VMware .vmx (config)', exts: ['vmx'], offset: 0, bytes: b('.encoding = "') },
  // --- Otros formatos comunes ----------------------------------------------
  { id: 'png', etiqueta: 'PNG', exts: ['png'], offset: 0, bytes: b('89504e470d0a1a0a0000000d49484452', true) },
  {
    id: 'ooxml',
    etiqueta: 'Office OOXML (docx/xlsx/pptx)',
    exts: ['docx', 'xlsx', 'pptx'],
    offset: 30,
    bytes: b('[Content_Types].xml'),
  },
];

// Extensión (en minúsculas, sin punto) del nombre de la entrada.
function extOf(name) {
  const base = name.replace(/\\/g, '/').split('/').pop() || '';
  const dot = base.lastIndexOf('.');
  return dot > 0 ? base.slice(dot + 1).toLowerCase() : '';
}

// Candidatos de texto plano para una entrada, según su extensión. Solo tiene
// sentido para entradas STORE (método 0): en DEFLATE la cabecera en claro no
// es el flujo cifrado. Devuelve [{ etiqueta, offset, plano }] con ≥12 bytes.
function candidatesForEntry(entry) {
  if (entry.method !== 0) return []; // STORE únicamente
  const ext = extOf(entry.name);
  if (!ext) return [];
  return SIGNATURES.filter((s) => s.exts.includes(ext) && s.bytes.length >= ATTACK_SIZE).map((s) => ({
    etiqueta: s.etiqueta,
    offset: s.offset,
    plano: s.bytes,
  }));
}

// Extensiones que el catálogo cubre (para mensajes de ayuda).
function coveredExtensions() {
  return [...new Set(SIGNATURES.flatMap((s) => s.exts))].sort();
}

module.exports = { SIGNATURES, candidatesForEntry, coveredExtensions, extOf };
