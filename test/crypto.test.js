'use strict';

const test = require('node:test');
const assert = require('node:assert');

const { readZip } = require('../lib/zip');
const { verify, decrypt } = require('../lib/verify');
const { fixturePath, loadManifest } = require('./helpers');

const manifest = loadManifest();

for (const fx of manifest) {
  test(`verifica la contraseña correcta: ${fx.file}`, () => {
    const zip = readZip(fixturePath(fx.file));
    const entry = zip.entries[0];
    assert.strictEqual(entry.encryption, fx.encryption);
    assert.ok(verify(entry, fx.password), 'la contraseña correcta debe validar');
  });

  test(`rechaza contraseñas incorrectas: ${fx.file}`, () => {
    const zip = readZip(fixturePath(fx.file));
    const entry = zip.entries[0];
    for (const wrong of ['', 'x', 'incorrecta', fx.password + 'x', fx.password.toUpperCase()]) {
      if (wrong === fx.password) continue;
      assert.ok(!verify(entry, wrong), `no debe validar "${wrong}"`);
    }
  });

  test(`descifra el contenido original: ${fx.file}`, () => {
    const zip = readZip(fixturePath(fx.file));
    const entry = zip.entries[0];
    const plain = decrypt(entry, fx.password).toString('utf8');
    assert.strictEqual(plain, fx.content);
  });
}

test('el verificador AES de 2 bytes filtra pero no confirma solo', () => {
  // La confirmación definitiva es el HMAC; el verificador es un pre-filtro.
  const aes = require('../lib/crypto-aes');
  const zip = readZip(fixturePath('aes256-store.zip'));
  const entry = zip.entries[0];
  // fast=true acepta solo por el verificador (podría dar falso positivo raro);
  // la contraseña correcta pasa ambos.
  assert.ok(aes.verifyPassword(entry.crypto, 'Secreto_2024', { fast: true }));
  assert.ok(aes.verifyPassword(entry.crypto, 'Secreto_2024', { fast: false }));
});

test('ZipCrypto usa el byte de mod-time cuando el bit 3 está activo', () => {
  const zip = readZip(fixturePath('zipcrypto-store.zip'));
  const entry = zip.entries[0];
  assert.ok((entry.flags & 0x08) !== 0, 'el fixture de zip usa data descriptor');
  assert.ok(verify(entry, 'clave123'));
});
