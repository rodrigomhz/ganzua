'use strict';

// Modos de obtención SIN contraseña (lib/loot): clasificación por entrada y
// rescate real. El rescate no descifra nada: lee las entradas sin cifrar y
// reconstruye las pequeñas desde el CRC-32 en claro.

const test = require('node:test');
const assert = require('node:assert');
const cp = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const { readZip } = require('../lib/zip');
const loot = require('../lib/loot');
const { runCli } = require('./helpers');

// --- clasificación (entradas simuladas) ---

test('classify: sin cifrar => plano; carpeta => directorio', () => {
  assert.strictEqual(loot.classify({ name: 'a.txt', encryption: 'none', uncompressedSize: 10 }).modo, 'plano');
  assert.strictEqual(loot.classify({ name: 'dir/', encryption: 'none', uncompressedSize: 0 }).modo, 'directorio');
});

test('classify: ZipCrypto pequeña => crc; grande => ninguno', () => {
  assert.strictEqual(loot.classify({ name: 'p', encryption: 'zipcrypto', uncompressedSize: 3 }).modo, 'crc');
  assert.strictEqual(loot.classify({ name: 'g', encryption: 'zipcrypto', uncompressedSize: 9 }).modo, 'ninguno');
});

test('classify: AES AE-1 pequeña => crc (el CRC está en claro)', () => {
  const e = { name: 'p', encryption: 'aes', aes: { version: 1 }, uncompressedSize: 2 };
  assert.strictEqual(loot.classify(e).modo, 'crc');
});

test('classify: AES AE-2 => ninguno (CRC=0, no expuesto)', () => {
  const e = { name: 'p', encryption: 'aes', aes: { version: 2 }, uncompressedSize: 2 };
  assert.strictEqual(loot.classify(e).modo, 'ninguno');
});

test('classify: entrada cifrada de 0 bytes => vacio', () => {
  assert.strictEqual(loot.classify({ name: 'e', encryption: 'zipcrypto', uncompressedSize: 0 }).modo, 'vacio');
});

test('classify: --maxbytes y --charset ajustan qué es recuperable', () => {
  const zc3 = { name: 'p', encryption: 'zipcrypto', uncompressedSize: 3 };
  assert.strictEqual(loot.classify(zc3, { maxBytes: 2 }).modo, 'ninguno');
  // 6 dígitos = 10^6 combinaciones: abordable con alfabeto restringido.
  const zc6 = { name: 'p', encryption: 'zipcrypto', uncompressedSize: 6 };
  assert.strictEqual(loot.classify(zc6).modo, 'ninguno'); // 256^6 inabordable
  assert.strictEqual(loot.classify(zc6, { charset: 'digits' }).modo, 'crc');
});

// --- rescate real (requiere `zip`) ---

const hasZip = (() => {
  try {
    return cp.spawnSync('zip', ['-v']).status === 0;
  } catch {
    return false;
  }
})();

const skipZip = hasZip ? false : 'requiere el comando `zip`';

test('rescate: recupera por CRC-32 una entrada ZipCrypto pequeña sin contraseña', { skip: skipZip }, async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'gz-loot-'));
  try {
    fs.writeFileSync(path.join(dir, 'pin.txt'), 'PIN');
    const zipPath = path.join(dir, 'zc.zip');
    // -0 STORE, -e cifrado ZipCrypto, -j sin ruta, contraseña larga irrelevante.
    const r = cp.spawnSync('zip', [
      '-q',
      '-0',
      '-e',
      '-j',
      '-P',
      'contraseña-larguísima-9Z',
      zipPath,
      path.join(dir, 'pin.txt'),
    ]);
    assert.strictEqual(r.status, 0);

    const zip = readZip(zipPath);
    assert.strictEqual(zip.entries[0].encryption, 'zipcrypto');
    const outDir = path.join(dir, 'out');
    const results = await loot.rescue(zip, zip.entries, { outDir });
    const rec = results.find((x) => x.nombre === 'pin.txt');
    assert.ok(rec && rec.ok, 'debe rescatar pin.txt');
    assert.strictEqual(rec.modo, 'crc');
    assert.strictEqual(fs.readFileSync(path.join(outDir, 'pin.txt'), 'latin1'), 'PIN');
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('rescate: extrae entradas sin cifrar sin contraseña', { skip: skipZip }, async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'gz-loot2-'));
  try {
    const content = 'documento público, sin cifrar\n';
    fs.writeFileSync(path.join(dir, 'libre.txt'), content);
    const zipPath = path.join(dir, 'plano.zip');
    const r = cp.spawnSync('zip', ['-q', '-j', zipPath, path.join(dir, 'libre.txt')]);
    assert.strictEqual(r.status, 0);

    const zip = readZip(zipPath);
    const outDir = path.join(dir, 'out');
    const results = await loot.rescue(zip, zip.entries, { outDir });
    const rec = results.find((x) => x.nombre === 'libre.txt');
    assert.ok(rec && rec.ok);
    assert.strictEqual(rec.modo, 'plano');
    assert.strictEqual(fs.readFileSync(path.join(outDir, 'libre.txt'), 'utf8'), content);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('CLI: `rescata --listar --json` clasifica sin escribir', { skip: skipZip }, () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'gz-loot3-'));
  try {
    fs.writeFileSync(path.join(dir, 'ok.txt'), 'Hi');
    const zipPath = path.join(dir, 'zc.zip');
    cp.spawnSync('zip', ['-q', '-0', '-e', '-j', '-P', 'x9Z-larga', zipPath, path.join(dir, 'ok.txt')]);
    const res = runCli(['rescata', zipPath, '--listar', '--json']);
    assert.strictEqual(res.status, 0);
    const json = JSON.parse(res.stdout);
    assert.strictEqual(json.rescatables, 1);
    assert.strictEqual(json.entradas[0].modo, 'crc');
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
