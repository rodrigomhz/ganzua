'use strict';

// Known-answer tests contra vectores públicos, independientes de los fixtures
// autogenerados con pyzipper. Si pyzipper y ganzua compartieran un mismo error,
// estos vectores lo detectarían.

const test = require('node:test');
const assert = require('node:assert');

const aes = require('../lib/crypto-aes');
const { buildZip2Hash } = require('../ganzua');

// Vector oficial de hashcat, modo 13600 (WinZip AES-256). Contraseña "hashcat".
// Fuente: https://hashcat.net/wiki/doku.php?id=example_hashes
const HASHCAT_13600 =
  '$zip2$*0*3*0*e3222d3b65b5a2785b192d31e39ff9de*1320*e*19648c3e063c82a9ad3ef08ed833*3135c79ecb86cd6f48fc*$/zip2$';

function entryFromZip2(hash) {
  const p = hash.split('*');
  // $zip2$ * type * strength * magic * salt * verify * datalen * data * auth * $/zip2$
  return {
    strength: Number(p[2]),
    salt: Buffer.from(p[4], 'hex'),
    verify: Buffer.from(p[5], 'hex'),
    ciphertext: Buffer.from(p[7], 'hex'),
    auth: Buffer.from(p[8], 'hex'),
  };
}

test('vector hashcat 13600: verifica la contraseña "hashcat"', () => {
  const crypto = entryFromZip2(HASHCAT_13600);
  assert.strictEqual(crypto.strength, 3); // AES-256
  assert.strictEqual(crypto.salt.length, 16);
  assert.ok(aes.verifyPassword(crypto, 'hashcat'), 'debe validar "hashcat"');
});

test('vector hashcat 13600: rechaza contraseñas incorrectas', () => {
  const crypto = entryFromZip2(HASHCAT_13600);
  for (const wrong of ['hashca', 'Hashcat', 'hashcat1', 'password', '']) {
    assert.ok(!aes.verifyPassword(crypto, wrong), `no debe validar "${wrong}"`);
  }
});

test('material reproduce exactamente el hash $zip2$ del vector', () => {
  const crypto = entryFromZip2(HASHCAT_13600);
  assert.strictEqual(buildZip2Hash({ crypto }), HASHCAT_13600);
});
