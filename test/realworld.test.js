'use strict';

// Casos reales que fallaban: nombres CP437/Unicode y ZIP con stub antepuesto
// (SFX .exe). Los ZIP se construyen a mano para no depender de herramientas.

const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const { readZip, parseCentralDirectory } = require('../lib/zip');
const { verify, decrypt } = require('../lib/verify');
const { crc32 } = require('../lib/crypto-zipcrypto');
const { fixturePath } = require('./helpers');

// ZIP mínimo de una entrada STORE sin cifrar.
function buildZip({ nameBytes, flags = 0, content = Buffer.from('hola\n'), extra = Buffer.alloc(0) }) {
  const n = nameBytes.length;
  const m = extra.length;
  const cs = content.length;
  const crc = crc32(content) >>> 0;

  const lh = Buffer.alloc(30);
  lh.writeUInt32LE(0x04034b50, 0);
  lh.writeUInt16LE(20, 4);
  lh.writeUInt16LE(flags, 6);
  lh.writeUInt32LE(crc, 14);
  lh.writeUInt32LE(cs, 18);
  lh.writeUInt32LE(cs, 22);
  lh.writeUInt16LE(n, 26);
  lh.writeUInt16LE(m, 28);
  const local = Buffer.concat([lh, nameBytes, extra, content]);

  const ch = Buffer.alloc(46);
  ch.writeUInt32LE(0x02014b50, 0);
  ch.writeUInt16LE(20, 4);
  ch.writeUInt16LE(20, 6);
  ch.writeUInt16LE(flags, 8);
  ch.writeUInt32LE(crc, 16);
  ch.writeUInt32LE(cs, 20);
  ch.writeUInt32LE(cs, 24);
  ch.writeUInt16LE(n, 28);
  ch.writeUInt16LE(m, 30);
  ch.writeUInt32LE(0, 42); // offset local
  const central = Buffer.concat([ch, nameBytes, extra]);

  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0);
  eocd.writeUInt16LE(1, 8);
  eocd.writeUInt16LE(1, 10);
  eocd.writeUInt32LE(central.length, 12);
  eocd.writeUInt32LE(local.length, 16);
  return Buffer.concat([local, central, eocd]);
}

function writeTmp(buf, name = 'a.zip') {
  const f = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'gz-rw-')), name);
  fs.writeFileSync(f, buf);
  return f;
}

test('nombre CP437 sin EFS se decodifica (año.txt)', () => {
  const buf = buildZip({ nameBytes: Buffer.from([0x61, 0xa4, 0x6f, 0x2e, 0x74, 0x78, 0x74]) }); // "a\xa4o.txt"
  const zip = parseCentralDirectory(buf);
  assert.strictEqual(zip.entries[0].name, 'año.txt');
});

test('nombre UTF-8 con EFS (bit 11) se decodifica como UTF-8', () => {
  const buf = buildZip({ nameBytes: Buffer.from('año.txt', 'utf8'), flags: 0x800 });
  const zip = parseCentralDirectory(buf);
  assert.strictEqual(zip.entries[0].name, 'año.txt');
});

test('el campo extra Unicode Path (0x7075) tiene prioridad', () => {
  const utf8 = Buffer.from('año.txt', 'utf8');
  const body = Buffer.concat([Buffer.from([0x01]), Buffer.alloc(4), utf8]); // version + nameCRC + name
  const extra = Buffer.concat([Buffer.from([0x75, 0x70]), Buffer.alloc(2), body]);
  extra.writeUInt16LE(body.length, 2);
  const buf = buildZip({ nameBytes: Buffer.from([0x61, 0xa4, 0x6f]), extra }); // nombre principal CP437 distinto
  const zip = parseCentralDirectory(buf);
  assert.strictEqual(zip.entries[0].name, 'año.txt');
});

test('ZIP con stub antepuesto (SFX .exe) se parsea y descifra', () => {
  const fixture = fs.readFileSync(fixturePath('zipcrypto-store.zip'));
  const stub = Buffer.from('MZ\x90\x00' + 'STUB EJECUTABLE '.repeat(80));
  const f = writeTmp(Buffer.concat([stub, fixture]), 'sfx.zip');
  const zip = readZip(f);
  assert.strictEqual(zip.entries[0].name, 'mensaje.txt');
  assert.ok(verify(zip.entries[0], 'clave123'), 'debe verificar pese al stub');
  assert.strictEqual(decrypt(zip.entries[0], 'clave123').toString('utf8'), 'contenido zipcrypto de prueba\n');
});

test('CLI extrae funciona sobre un ZIP con stub (SFX)', () => {
  const { runCli } = require('./helpers');
  const fixture = fs.readFileSync(fixturePath('aes256-store.zip'));
  const f = writeTmp(Buffer.concat([Buffer.alloc(2048, 0x41), fixture]), 'sfx-aes.zip');
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'gz-rw-'));
  const { status } = runCli(['extrae', f, 'Secreto_2024', '--salida', dir]);
  assert.strictEqual(status, 0);
  assert.strictEqual(
    fs.readFileSync(path.join(dir, 'nota.txt'), 'utf8'),
    'Hola mundo, contenido de prueba para ganzua.\n',
  );
});
