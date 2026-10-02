'use strict';

const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const formato = require('../lib/format');
const { runCli, fixturePath } = require('./helpers');

function buf(...bytes) {
  return Buffer.from(bytes);
}

test('detectFormat reconoce las firmas de los formatos populares', () => {
  assert.strictEqual(formato.detectFormat(buf(0x50, 0x4b, 0x03, 0x04)), 'zip');
  assert.strictEqual(formato.detectFormat(buf(0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c)), '7z');
  assert.strictEqual(formato.detectFormat(buf(0x52, 0x61, 0x72, 0x21, 0x1a, 0x07, 0x01, 0x00)), 'rar5');
  assert.strictEqual(formato.detectFormat(buf(0x52, 0x61, 0x72, 0x21, 0x1a, 0x07, 0x00)), 'rar4');
  assert.strictEqual(formato.detectFormat(buf(0x1f, 0x8b)), 'gzip');
  assert.strictEqual(formato.detectFormat(buf(0x42, 0x5a, 0x68)), 'bzip2');
  assert.strictEqual(formato.detectFormat(buf(0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00)), 'xz');
  assert.strictEqual(formato.detectFormat(buf(0x00, 0x11, 0x22)), 'desconocido');
});

test('info da la vía de ataque: ZIP nativo, 7z y RAR vía hashcat', () => {
  assert.strictEqual(formato.info('zip').nativo, true);
  assert.match(formato.info('7z').guia, /11600/);
  assert.match(formato.info('rar5').guia, /13000/);
  assert.match(formato.info('rar4').guia, /12500/);
});

test('detectFile identifica un ZIP real y un 7z falso', () => {
  assert.strictEqual(formato.detectFile(fixturePath('zipcrypto-store.zip')), 'zip');
  const f = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'gz-fmt-')), 'x.7z');
  fs.writeFileSync(f, Buffer.concat([buf(0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c, 0x00, 0x04), Buffer.alloc(24)]));
  assert.strictEqual(formato.detectFile(f), '7z');
});

test('CLI formato informa y romper sobre un no-ZIP guía al usuario', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'gz-fmt-'));
  const f = path.join(dir, 'a.7z');
  fs.writeFileSync(f, Buffer.concat([buf(0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c, 0x00, 0x04), Buffer.alloc(64)]));

  const fmt = runCli(['formato', '--json', f]);
  assert.strictEqual(fmt.status, 0);
  assert.strictEqual(JSON.parse(fmt.stdout).formato, '7z');

  const romper = runCli(['romper', f]);
  assert.notStrictEqual(romper.status, 0);
  assert.match(romper.stderr, /7-Zip|11600/);
});
