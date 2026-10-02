'use strict';

const test = require('node:test');
const assert = require('node:assert');

const { readZip, parseZip64Extra } = require('../lib/zip');
const { verify, decrypt } = require('../lib/verify');
const { fixturePath } = require('./helpers');

test('parseZip64Extra lee los campos de 64 bits presentes, en orden', () => {
  const body = Buffer.alloc(24);
  body.writeBigUInt64LE(5_000_000_000n, 0); // uncompressed
  body.writeBigUInt64LE(4_000_000_000n, 8); // compressed
  body.writeBigUInt64LE(9_000_000_000n, 16); // offset
  const extra = Buffer.concat([Buffer.from([0x01, 0x00, 24, 0x00]), body]);

  const all = parseZip64Extra(extra, { usize: true, csize: true, offset: true, disk: false });
  assert.strictEqual(all.uncompressedSize, 5_000_000_000);
  assert.strictEqual(all.compressedSize, 4_000_000_000);
  assert.strictEqual(all.localOffset, 9_000_000_000);
});

test('parseZip64Extra respeta qué campos overflowaron (solo compressed)', () => {
  // Solo el tamaño comprimido está en ZIP64: es el primer (y único) valor.
  const body = Buffer.alloc(8);
  body.writeBigUInt64LE(4_294_967_296n, 0); // 4 GiB exactos
  const extra = Buffer.concat([Buffer.from([0x01, 0x00, 8, 0x00]), body]);
  const r = parseZip64Extra(extra, { usize: false, csize: true, offset: false, disk: false });
  assert.strictEqual(r.compressedSize, 4_294_967_296);
  assert.strictEqual(r.uncompressedSize, undefined);
  assert.strictEqual(r.localOffset, undefined);
});

test('un ZIP64 real se parsea con el tamaño correcto y descifra', () => {
  const zip = readZip(fixturePath('zip64-store.zip'));
  const e = zip.entries[0];
  assert.strictEqual(e.uncompressedSize, 26, 'talla real desde el extra 0x0001, no 0xffffffff');
  assert.ok(verify(e, 'clave64'));
  assert.strictEqual(decrypt(e, 'clave64').toString('utf8'), 'contenido zip64 de prueba\n');
});
