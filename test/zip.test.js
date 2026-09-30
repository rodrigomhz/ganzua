'use strict';

const test = require('node:test');
const assert = require('node:assert');

const { readZip, firstEncryptedEntry, detectEncryption } = require('../lib/zip');
const { fixturePath } = require('./helpers');

test('detecta el método de cifrado por entrada', () => {
  const aes = readZip(fixturePath('aes256-store.zip'));
  assert.strictEqual(aes.entries[0].encryption, 'aes');
  assert.strictEqual(aes.entries[0].aes.strength, 3);
  assert.strictEqual(aes.entries[0].method, 0); // STORE real bajo AES

  const zc = readZip(fixturePath('zipcrypto-deflate.zip'));
  assert.strictEqual(zc.entries[0].encryption, 'zipcrypto');
  assert.strictEqual(zc.entries[0].method, 8); // DEFLATE
});

test('extrae el material AES con longitudes coherentes', () => {
  const zip = readZip(fixturePath('aes256-store.zip'));
  const c = zip.entries[0].crypto;
  assert.strictEqual(c.salt.length, 16); // AES-256 => salt 16 B
  assert.strictEqual(c.verify.length, 2);
  assert.strictEqual(c.auth.length, 10);
  // csize = salt + verify + ct + auth
  assert.strictEqual(zip.entries[0].compressedSize, 16 + 2 + c.ciphertext.length + 10);
});

test('firstEncryptedEntry devuelve la primera entrada cifrada', () => {
  const zip = readZip(fixturePath('aes256-store.zip'));
  const e = firstEncryptedEntry(zip);
  assert.ok(e);
  assert.strictEqual(e.encryption, 'aes');
});

test('detectEncryption clasifica método/flags', () => {
  assert.strictEqual(detectEncryption(99, 0x1), 'aes');
  assert.strictEqual(detectEncryption(8, 0x1), 'zipcrypto');
  assert.strictEqual(detectEncryption(8, 0x0), 'none');
});
