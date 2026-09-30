'use strict';

const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const zc = require('../lib/crypto-zipcrypto');
const bkcrack = require('../lib/bkcrack');
const { readZip } = require('../lib/zip');
const { runCli, fixturePath } = require('./helpers');

function keysFor(password) {
  const k = new zc.Keys(password);
  return [k.k0, k.k1, k.k2];
}

test('decryptWithKeys reproduce el descifrado por contraseña', () => {
  for (const [file, pw] of [
    ['zipcrypto-store.zip', 'clave123'],
    ['zipcrypto-deflate.zip', 'otra_clave'],
  ]) {
    const c = readZip(fixturePath(file)).entries[0].crypto;
    const viaPw = zc.decrypt(c, pw).toString('utf8');
    const viaKeys = zc.decryptWithKeys(c, keysFor(pw)).toString('utf8');
    assert.strictEqual(viaKeys, viaPw, `${file}: claves vs contraseña`);
  }
});

test('Keys.fromState reconstruye el estado interno', () => {
  const a = new zc.Keys('clave123');
  const b = zc.Keys.fromState(a.k0, a.k1, a.k2);
  assert.strictEqual(b.k0, a.k0);
  assert.strictEqual(b.k1, a.k1);
  assert.strictEqual(b.k2, a.k2);
});

test('bkcrack.buildArgs (fichero de texto plano y hex)', () => {
  assert.deepStrictEqual(bkcrack.buildArgs({ zip: 'a.zip', entry: 'x.txt', plainFile: 'p.bin' }), [
    '-C',
    'a.zip',
    '-c',
    'x.txt',
    '-p',
    'p.bin',
  ]);
  assert.deepStrictEqual(bkcrack.buildArgs({ zip: 'a.zip', entry: 'x.txt', offset: 4, hex: 'deadbeef' }), [
    '-C',
    'a.zip',
    '-c',
    'x.txt',
    '-x',
    '4',
    'deadbeef',
  ]);
});

test('bkcrack.parseKeys extrae las 3 claves internas', () => {
  const out = 'Attack on 1 Z value(s)\nKeys\n1a2b3c4d 5e6f7081 92a3b4c5\n';
  assert.deepStrictEqual(bkcrack.parseKeys(out), [0x1a2b3c4d, 0x5e6f7081, 0x92a3b4c5]);
  assert.strictEqual(bkcrack.parseKeys('sin claves aquí'), null);
});

test('bkcrack.isAvailable devuelve un booleano sin lanzar', () => {
  assert.strictEqual(typeof bkcrack.isAvailable(), 'boolean');
});

test('CLI extrae --claves descifra ZipCrypto sin contraseña', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'gz-kx-'));
  const keys = keysFor('clave123')
    .map((k) => k.toString(16).padStart(8, '0'))
    .join(':');
  const { status } = runCli(['extrae', fixturePath('zipcrypto-store.zip'), '--claves', keys, '--salida', dir]);
  assert.strictEqual(status, 0);
  assert.strictEqual(fs.readFileSync(path.join(dir, 'mensaje.txt'), 'utf8'), 'contenido zipcrypto de prueba\n');
});

test('CLI extrae --claves rechaza claves incorrectas', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'gz-kx-'));
  const { status, stderr } = runCli([
    'extrae',
    fixturePath('zipcrypto-store.zip'),
    '--claves',
    '11111111:22222222:33333333',
    '--salida',
    dir,
  ]);
  assert.notStrictEqual(status, 0);
  assert.match(stderr, /CRC no coincide|no descifran/);
});

test('CLI textoplano sin bkcrack da instrucciones claras', () => {
  if (bkcrack.isAvailable()) return;
  const { status, stderr } = runCli(['textoplano', fixturePath('zipcrypto-store.zip'), '--plano-hex', 'deadbeef']);
  assert.notStrictEqual(status, 0);
  assert.match(stderr, /bkcrack/);
  assert.match(stderr, /--claves/);
});
