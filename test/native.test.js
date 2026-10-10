'use strict';

// Addon N-API (ataque ZipCrypto Biham-Kocher en C++). El módulo `lib/native`
// es opcional: si el addon no está compilado (`npm run build:native`), expone
// available=false y la herramienta usa el motor JS. Estos tests validan:
//   1. la forma del módulo (siempre),
//   2. que, cuando el addon está disponible, recupera exactamente las mismas
//      claves internas que el motor JS y descifra el contenido (e2e real).
// El e2e usa texto plano de alta entropía para que la reducción Z sea efectiva
// (con texto plano de baja entropía el espacio de búsqueda es enorme).

const test = require('node:test');
const assert = require('node:assert');
const cp = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const native = require('../lib/native');
const zc = require('../lib/crypto-zipcrypto');
const { readZip } = require('../lib/zip');

test('lib/native expone la interfaz esperada', () => {
  assert.strictEqual(typeof native.available, 'boolean');
  assert.strictEqual(typeof native.attack, 'function');
});

test('sin addon, attack() falla de forma clara', { skip: native.available }, () => {
  assert.throws(() => native.attack(Buffer.alloc(0), Buffer.alloc(0), 0, 0), /addon nativo no disponible/);
});

const hasZip = (() => {
  try {
    return cp.spawnSync('zip', ['-h']).status === 0 || cp.spawnSync('zip', ['-v']).status === 0;
  } catch {
    return false;
  }
})();

// e2e: el addon recupera las claves y descifra, idéntico al motor JS. Sólo si
// el addon está compilado y `zip` está disponible para crear el fixture.
test(
  'e2e: el addon nativo recupera las claves y descifra',
  { skip: !native.available || !hasZip ? 'requiere addon compilado y `zip`' : false },
  () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'gz-native-'));
    try {
      // Texto plano determinista de alta entropía (STORE => texto plano = contenido).
      const plain = Buffer.alloc(300);
      for (let i = 0; i < plain.length; i++) plain[i] = (i * 131 + 17) & 0xff;
      const src = path.join(dir, 'data.bin');
      fs.writeFileSync(src, plain);
      const zipPath = path.join(dir, 'e2e.zip');
      const r = cp.spawnSync('zip', ['-q', '-0', '-e', '-j', '-P', 'clave123', zipPath, src]);
      assert.strictEqual(r.status, 0, 'zip debe crear el fixture');

      const c = readZip(zipPath).entries[0].crypto;
      const ciphertext = Buffer.concat([c.header, c.body]);
      const keys = native.attack(ciphertext, plain, 0, 0);

      const exp = new zc.Keys('clave123');
      assert.ok(keys, 'el addon debe recuperar las claves');
      assert.deepStrictEqual(keys, [exp.k0, exp.k1, exp.k2]);
      assert.strictEqual(zc.decryptWithKeys(c, keys).toString('latin1'), plain.toString('latin1'));
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  },
);
