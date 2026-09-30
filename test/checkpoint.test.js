'use strict';

const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const checkpoint = require('../lib/checkpoint');
const { searchAsync } = require('../lib/search');
const { searchParallel } = require('../lib/search-parallel');
const { readZip } = require('../lib/zip');
const { fixturePath } = require('./helpers');

function tmpFile() {
  return path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'gz-cp-')), 'cp.json');
}

test('checkpoint: firma estable y sensible a la configuración', () => {
  const a = checkpoint.signature('/x/a.zip', 0, { agresivo: false });
  const b = checkpoint.signature('/x/a.zip', 0, { agresivo: false });
  const c = checkpoint.signature('/x/a.zip', 0, { agresivo: true });
  assert.strictEqual(a, b);
  assert.notStrictEqual(a, c);
});

test('checkpoint: save/load/remove round-trip', () => {
  const f = tmpFile();
  checkpoint.save(f, { firma: 'abc', archivo: '/x/a.zip', entrada: 0, position: 1234, total: 9999 });
  const cp = checkpoint.load(f);
  assert.strictEqual(cp.position, 1234);
  assert.strictEqual(cp.firma, 'abc');
  checkpoint.remove(f);
  assert.strictEqual(checkpoint.load(f), null);
});

test('searchAsync: startAt salta candidatas ya probadas (resume)', async () => {
  const zip = readZip(fixturePath('aes256-store.zip'));
  const entry = zip.entries[0];
  const stream = () => ['a', 'b', 'Secreto_2024', 'c'];
  const hit = await searchAsync(entry, stream(), { startAt: 2 });
  assert.strictEqual(hit.found, true);
  assert.strictEqual(hit.position, 3);
  const miss = await searchAsync(entry, stream(), { startAt: 3 }); // salta la correcta
  assert.strictEqual(miss.found, false);
  assert.strictEqual(miss.exhausted, true);
});

test('searchAsync: abort deja stopped y posición', async () => {
  const zip = readZip(fixturePath('aes256-store.zip'));
  const entry = zip.entries[0];
  function* many() {
    for (let i = 0; i < 1e7; i++) yield `nope_${i}`;
  }
  const ac = new AbortController();
  setTimeout(() => ac.abort(), 60);
  const res = await searchAsync(entry, many(), { signal: ac.signal });
  assert.strictEqual(res.stopped, true);
  assert.ok(res.position > 0, 'debe haber avanzado algo');
});

test('searchAsync: onCheckpoint reporta posiciones crecientes', async () => {
  const zip = readZip(fixturePath('aes256-store.zip'));
  const entry = zip.entries[0];
  const positions = [];
  await searchAsync(entry, Array.from({ length: 2000 }, (_, i) => `x_${i}`), {
    checkpointEvery: 500,
    onCheckpoint: (p) => positions.push(p),
  });
  assert.ok(positions.length >= 2, `esperaba varios checkpoints, hubo ${positions.length}`);
  for (let i = 1; i < positions.length; i++) assert.ok(positions[i] > positions[i - 1]);
});

test('searchParallel: startAt resume y posición comprometida', async () => {
  const zip = readZip(fixturePath('aes256-store.zip'));
  const entry = zip.entries[0];
  const stream = [...Array.from({ length: 300 }, (_, i) => `d${i}`), 'Secreto_2024'];
  const hit = await searchParallel(entry, [...stream], { workers: 3, batchSize: 50 });
  assert.strictEqual(hit.found, true);
  // Saltando más allá de la correcta (índice 300) no se encuentra.
  const miss = await searchParallel(entry, [...stream], { workers: 3, batchSize: 50, startAt: 301 });
  assert.strictEqual(miss.found, false);
  assert.strictEqual(miss.exhausted, true);
  assert.strictEqual(miss.position, 301);
});

test('searchParallel: abort previo deja stopped', async () => {
  const zip = readZip(fixturePath('aes256-store.zip'));
  const entry = zip.entries[0];
  const ac = new AbortController();
  ac.abort();
  const res = await searchParallel(entry, Array.from({ length: 10000 }, (_, i) => `n${i}`), { workers: 2, signal: ac.signal });
  assert.strictEqual(res.stopped, true);
});
