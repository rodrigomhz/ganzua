'use strict';

// Robustez frente a "data descriptor" (bit 3 de flags): cuando está activo, la
// cabecera LOCAL lleva crc/tamaños a cero y los valores reales van en el
// directorio central (y en un descriptor tras los datos). ganzua debe apoyarse
// solo en el directorio central para los tamaños y en las longitudes de
// nombre/extra locales para localizar los datos — nunca en los tamaños locales.

const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const { readZip } = require('../lib/zip');
const { verify, decrypt } = require('../lib/verify');
const { fixturePath } = require('./helpers');

// Simula una entrada con data descriptor: activa el bit 3 y pone a cero
// crc/csize/usize en la cabecera local del primer registro.
function forgeDataDescriptor(srcPath) {
  const buf = Buffer.from(fs.readFileSync(srcPath));
  assert.strictEqual(buf.readUInt32LE(0), 0x04034b50, 'primer registro = cabecera local');
  buf.writeUInt16LE(buf.readUInt16LE(6) | 0x08, 6); // flags locales |= bit 3
  buf.writeUInt32LE(0, 14); // crc32 -> 0
  buf.writeUInt32LE(0, 18); // compressed size -> 0
  buf.writeUInt32LE(0, 22); // uncompressed size -> 0
  // Refleja el bit 3 también en el registro del directorio central.
  const cd = buf.indexOf(Buffer.from([0x50, 0x4b, 0x01, 0x02]));
  buf.writeUInt16LE(buf.readUInt16LE(cd + 8) | 0x08, cd + 8);
  const tmp = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'gz-dd-')), path.basename(srcPath));
  fs.writeFileSync(tmp, buf);
  return tmp;
}

test('AES: parsea correctamente con tamaños locales a cero (data descriptor)', () => {
  const forged = forgeDataDescriptor(fixturePath('aes256-store.zip'));
  const zip = readZip(forged);
  const entry = zip.entries[0];
  assert.ok((entry.flags & 0x08) !== 0, 'bit 3 activo');
  // Los tamaños vienen del directorio central, no de la cabecera local.
  assert.strictEqual(entry.compressedSize, 73);
  assert.ok(verify(entry, 'Secreto_2024'), 'la verificación sigue funcionando');
  assert.strictEqual(decrypt(entry, 'Secreto_2024').toString('utf8'), 'Hola mundo, contenido de prueba para ganzua.\n');
});

test('ZipCrypto: el check byte usa mod-time cuando el bit 3 está activo', () => {
  // Los fixtures de Info-ZIP ya se generan con data descriptor (bit 3).
  for (const f of ['zipcrypto-store.zip', 'zipcrypto-deflate.zip']) {
    const zip = readZip(fixturePath(f));
    const entry = zip.entries[0];
    assert.ok((entry.flags & 0x08) !== 0, `${f}: bit 3 activo`);
    const pw = f.includes('store') ? 'clave123' : 'otra_clave';
    assert.ok(verify(entry, pw), `${f}: verifica con mod-time check byte`);
  }
});
