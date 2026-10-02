'use strict';

const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const enc = require('../lib/encoding');
const zc = require('../lib/crypto-zipcrypto');
const aes = require('../lib/crypto-aes');
const { runCli, fixturePath } = require('./helpers');

test('encodeCp437 mapea acentos y ñ a sus bytes CP437', () => {
  assert.strictEqual(enc.encodeCp437('ñ').toString('hex'), 'a4');
  assert.strictEqual(enc.encodeCp437('contraseña').toString('hex'), '636f6e7472617365a461');
  assert.strictEqual(enc.encodeCp437('abc').toString('hex'), '616263'); // ASCII intacto
  assert.strictEqual(enc.encodeCp437('中'), null); // no representable
});

test('toBytes: utf8 por defecto, cp437, y Buffer tal cual', () => {
  assert.strictEqual(enc.toBytes('ñ').toString('hex'), 'c3b1'); // utf8
  assert.strictEqual(enc.toBytes('ñ', 'cp437').toString('hex'), 'a4');
  const b = Buffer.from([1, 2, 3]);
  assert.strictEqual(enc.toBytes(b), b);
});

test('la codificación string+cp437 equivale a los bytes crudos (ZipCrypto y AES)', () => {
  const a = new zc.Keys('ñ', 'cp437');
  const b = new zc.Keys(Buffer.from([0xa4]));
  assert.deepStrictEqual([a.k0, a.k1, a.k2], [b.k0, b.k1, b.k2]);

  const salt = Buffer.alloc(16, 7);
  const d1 = aes.deriveKeys('ñ', salt, 32, 'cp437').pwdVerify;
  const d2 = aes.deriveKeys(Buffer.from([0xa4]), salt, 32).pwdVerify;
  assert.ok(d1.equals(d2));
});

test('CLI: una contraseña CP437 falla en UTF-8 y acierta con --cp437', () => {
  const utf8 = runCli(['verifica', fixturePath('zipcrypto-cp437.zip'), 'contraseña']);
  assert.strictEqual(utf8.status, 1, 'UTF-8 no debe validar la contraseña CP437');
  const cp437 = runCli(['verifica', '--cp437', fixturePath('zipcrypto-cp437.zip'), 'contraseña']);
  assert.strictEqual(cp437.status, 0, '--cp437 debe validar');
});

test('CLI: extrae --cp437 descifra el contenido', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'gz-cp-'));
  const { status } = runCli(['extrae', '--cp437', fixturePath('zipcrypto-cp437.zip'), 'contraseña', '--salida', dir]);
  assert.strictEqual(status, 0);
  assert.strictEqual(fs.readFileSync(path.join(dir, 'cp437.txt'), 'utf8'), 'contenido con contrasena CP437\n');
});
