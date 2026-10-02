'use strict';

// Ataque nativo Biham-Kocher (port de bkcrack). Validación por partes:
//   1. primitivas (crc32^-1, Keys hacia atrás),
//   2. núcleo del ataque: partiendo del Z verdadero recupera las claves,
//   3. la reducción Z incluye el Z verdadero entre las candidatas.
// (2)+(3) demuestran que el ataque completo recupera las claves, sin pagar la
// búsqueda completa. El e2e completo (lento) va detrás de GANZUA_SLOW=1.

const test = require('node:test');
const assert = require('node:assert');

const zc = require('../lib/crypto-zipcrypto');
const attack = require('../lib/zipcrypto-attack');
const { readZip } = require('../lib/zip');
const { fixturePath } = require('./helpers');

const PASSWORD = 'clave123';
const PLAINTEXT = Buffer.from('contenido zipcrypto de prueba\n'); // STORE => texto plano = contenido

function loadStore() {
  const c = readZip(fixturePath('zipcrypto-store.zip')).entries[0].crypto;
  const ciphertext = Buffer.concat([c.header, c.body]);
  return { c, ciphertext };
}

// Estado Z[2,32) verdadero en la posición `zrIndex` del keystream.
function trueZat(ciphertext, offset, zrIndex, password) {
  const k = new zc.Keys(password);
  const absPos = offset + zrIndex;
  for (let p = 0; p < absPos; p++) k.update((ciphertext[p] ^ k.getK()) & 0xff);
  return (k.k2 & 0xfffffffc) >>> 0;
}

test('crc32^-1 es la inversa de crc32', () => {
  for (const x of [0, 1, 0x12345678, 0xffffffff, 0xdeadbeef]) {
    for (const b of [0, 1, 0x55, 0xff]) {
      const y = zc.crc32Byte(x, b);
      assert.strictEqual(zc.crc32InvByte(y, b), x >>> 0);
    }
  }
});

test('Keys.updateBackward deshace update', () => {
  const k = new zc.Keys(PASSWORD);
  const before = [k.k0, k.k1, k.k2];
  k.update(0x42);
  k.updateBackwardPlaintext(0x42);
  assert.deepStrictEqual([k.k0, k.k1, k.k2], before);
});

test('el núcleo del ataque recupera las claves desde el Z verdadero', () => {
  const { ciphertext } = loadStore();
  const data = attack.makeData(ciphertext, PLAINTEXT, 0);
  const zrIndex = data.keystream.length - 1;
  const trueZ = trueZat(ciphertext, data.offset, zrIndex, PASSWORD);
  const rec = attack.runAttack(data, [trueZ], zrIndex);
  const exp = new zc.Keys(PASSWORD);
  assert.ok(rec, 'debe recuperar claves');
  assert.deepStrictEqual(rec, [exp.k0, exp.k1, exp.k2]);
});

test('la reducción Z conserva el Z verdadero entre las candidatas', () => {
  const { ciphertext } = loadStore();
  const data = attack.makeData(ciphertext, PLAINTEXT, 0);
  const { candidates, index } = attack.zreduction(data.keystream);
  const trueZ = trueZat(ciphertext, data.offset, index, PASSWORD);
  assert.ok(new Set(candidates).has(trueZ), 'el Z verdadero debe sobrevivir a la reducción');
});

test('las claves recuperadas descifran el contenido', () => {
  const { c, ciphertext } = loadStore();
  const data = attack.makeData(ciphertext, PLAINTEXT, 0);
  const zrIndex = data.keystream.length - 1;
  const keys = attack.runAttack(data, [trueZat(ciphertext, data.offset, zrIndex, PASSWORD)], zrIndex);
  assert.strictEqual(zc.decryptWithKeys(c, keys).toString('utf8'), PLAINTEXT.toString('utf8'));
});

// End-to-end completo (reducción + búsqueda paralela). Lento (~15-30 s) y
// necesita texto plano de alta entropía, así que genera un fixture propio y
// sólo corre con GANZUA_SLOW=1.
test('e2e: ataque nativo completo recupera las claves', { skip: !process.env.GANZUA_SLOW }, async () => {
  const cp = require('node:child_process');
  const fs = require('node:fs');
  const os = require('node:os');
  const path = require('node:path');
  const { recoverKeysParallel } = require('../lib/zipcrypto-attack-parallel');

  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'gz-bk-'));
  const plain = Buffer.alloc(300);
  for (let i = 0; i < plain.length; i++) plain[i] = (i * 131 + 17) & 0xff; // determinista, alta entropía
  const src = path.join(dir, 'data.bin');
  fs.writeFileSync(src, plain);
  const zipPath = path.join(dir, 'e2e.zip');
  cp.spawnSync('zip', ['-q', '-0', '-e', '-j', '-P', 'clave123', zipPath, src]);

  const c = readZip(zipPath).entries[0].crypto;
  const ciphertext = Buffer.concat([c.header, c.body]);
  const keys = await recoverKeysParallel(ciphertext, plain, 0, {});
  const exp = new zc.Keys('clave123');
  assert.ok(keys, 'debe recuperar claves');
  assert.deepStrictEqual(keys, [exp.k0, exp.k1, exp.k2]);
  assert.strictEqual(zc.decryptWithKeys(c, keys).toString('latin1'), plain.toString('latin1'));
  fs.rmSync(dir, { recursive: true, force: true });
});
