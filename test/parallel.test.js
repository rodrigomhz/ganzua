'use strict';

const test = require('node:test');
const assert = require('node:assert');

const { readZip } = require('../lib/zip');
const { searchParallel } = require('../lib/search-parallel');
const { search } = require('../lib/search');
const { fixturePath } = require('./helpers');

test('searchParallel encuentra la contraseña presente en el flujo', async () => {
  const zip = readZip(fixturePath('aes256-store.zip'));
  const entry = zip.entries[0];
  const decoys = Array.from({ length: 2000 }, (_, i) => `decoy_${i}`);
  const stream = [...decoys, 'Secreto_2024', ...decoys];
  const res = await searchParallel(entry, stream, { workers: 3, batchSize: 200 });
  assert.strictEqual(res.found, true);
  assert.strictEqual(res.password, 'Secreto_2024');
});

test('searchParallel devuelve no-encontrada cuando la clave no está', async () => {
  const zip = readZip(fixturePath('aes256-store.zip'));
  const entry = zip.entries[0];
  const stream = Array.from({ length: 500 }, (_, i) => `nope_${i}`);
  const res = await searchParallel(entry, stream, { workers: 3, batchSize: 64 });
  assert.strictEqual(res.found, false);
  assert.strictEqual(res.password, null);
  assert.strictEqual(res.tried, 500);
});

test('parallel y secuencial coinciden en el resultado', async () => {
  const zip = readZip(fixturePath('aes256-store.zip'));
  const entry = zip.entries[0];
  const stream = ['a', 'b', 'Secreto_2024', 'c'];
  const seq = search(entry, [...stream]);
  const par = await searchParallel(entry, [...stream], { workers: 2, batchSize: 1 });
  assert.strictEqual(seq.found, par.found);
  assert.strictEqual(seq.password, par.password);
});

test('searchParallel respeta el límite', async () => {
  const zip = readZip(fixturePath('aes256-store.zip'));
  const entry = zip.entries[0];
  const stream = Array.from({ length: 10000 }, (_, i) => `x_${i}`);
  const res = await searchParallel(entry, stream, { workers: 2, batchSize: 100, limit: 300 });
  assert.strictEqual(res.found, false);
  assert.ok(res.tried <= 300, `tried=${res.tried} debe ser <= 300`);
});
