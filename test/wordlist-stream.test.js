'use strict';

// Wordlist en streaming (memoria constante) para romper/busca. Verifica que
// wordSource() produce las mismas líneas que cargar el fichero, que es
// rebobinable (varias pasadas), y que trocea bien en los límites de chunk
// (64 KiB) sin corromper UTF-8. Así una wordlist enorme no agota la RAM.

const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const candidates = require('../lib/candidates');

function tmp(content) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'gz-wl-'));
  const file = path.join(dir, 'words.txt');
  fs.writeFileSync(file, content);
  return { dir, file };
}

test('wordSource: líneas no vacías, sin CR final, salta blancos', () => {
  const { dir, file } = tmp('uno\r\ndos\n\n  tres  \ncuatro');
  try {
    assert.deepStrictEqual([...candidates.wordSource(file)], ['uno', 'dos', '  tres  ', 'cuatro']);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('wordSource es rebobinable (dos pasadas idénticas)', () => {
  const { dir, file } = tmp('a\nb\nc\n');
  try {
    const src = candidates.wordSource(file);
    assert.deepStrictEqual([...src], ['a', 'b', 'c']);
    assert.deepStrictEqual([...src], ['a', 'b', 'c']); // reabre el fichero
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('wordSource conserva líneas que cruzan el límite de chunk (64 KiB)', () => {
  const long = 'x'.repeat(70000); // > 64 KiB en una sola línea
  const { dir, file } = tmp(`corta\n${long}\nfin\n`);
  try {
    const out = [...candidates.wordSource(file)];
    assert.deepStrictEqual(out, ['corta', long, 'fin']);
    assert.strictEqual(out[1].length, 70000);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('wordSource no corrompe UTF-8 partido entre chunks', () => {
  // 'ñ' (0xC3 0xB1) colocada de modo que su primer byte sea el último del
  // primer chunk de 65536 bytes y el segundo byte abra el siguiente.
  const line1 = 'a'.repeat(65535) + 'ñ';
  const { dir, file } = tmp(`${line1}\núltimo\n`);
  try {
    const out = [...candidates.wordSource(file)];
    assert.strictEqual(out.length, 2);
    assert.strictEqual(out[0], line1); // 'ñ' intacta
    assert.strictEqual(out[1], 'último');
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('romperCandidates sobre wordSource: la pasada 1 son las palabras crudas', () => {
  const { dir, file } = tmp('hola\nmundo\n');
  try {
    const words = candidates.wordSource(file);
    const it = candidates.romperCandidates({ words });
    assert.strictEqual(it.next().value, 'hola');
    assert.strictEqual(it.next().value, 'mundo');
    // tras las palabras crudas vienen mutaciones (capitalización, etc.)
    assert.strictEqual(it.next().value, 'Hola');
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('estimateCount funciona con una fuente rebobinable', () => {
  const { dir, file } = tmp('uno\ndos\ntres\n');
  try {
    const nStream = candidates.estimateCount({ words: candidates.wordSource(file) });
    const nArray = candidates.estimateCount({ words: ['uno', 'dos', 'tres'] });
    assert.strictEqual(nStream, nArray);
    assert.ok(nStream > 0);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
