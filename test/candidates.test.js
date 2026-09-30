'use strict';

const test = require('node:test');
const assert = require('node:assert');

const candidates = require('../lib/candidates');

function collect(iter, max = Infinity) {
  const out = [];
  for (const x of iter) {
    out.push(x);
    if (out.length >= max) break;
  }
  return out;
}

test('la wordlist incluida carga y no está vacía', () => {
  const words = candidates.loadBundledWordlist();
  assert.ok(words.length > 100, 'debe tener cientos de entradas');
  assert.ok(words.includes('password'));
  assert.ok(words.includes('contraseña'));
});

test('genera los patrones documentados (palabra+año, mayúscula+número, año+sufijo)', () => {
  const words = ['madrid', 'password'];
  const set = new Set(collect(candidates.romperCandidates({ words, year: 2024 })));
  assert.ok(set.has('madrid'), 'palabra tal cual');
  assert.ok(set.has('Madrid'), 'capitalizada');
  assert.ok(set.has('password1'), 'palabra+sufijo');
  assert.ok(set.has('Password1'), 'mayúscula+número');
  assert.ok(set.has('madrid2024'), 'palabra+año');
  assert.ok(set.has('Madrid2024'), 'mayúscula+año');
  assert.ok(set.has('2024!'), 'año+sufijo');
});

test('el modo agresivo amplía el espacio de búsqueda', () => {
  const words = ['madrid'];
  const normal = candidates.estimateCount({ words, year: 2024 });
  const agresivo = candidates.estimateCount({ words, aggressive: true, year: 2024 });
  assert.ok(agresivo > normal * 3, 'agresivo debe ser bastante mayor');
});

test('estimateCount coincide con el recuento real (muestra pequeña)', () => {
  const words = ['madrid', 'sol', 'ana'];
  const est = candidates.estimateCount({ words, year: 2024 });
  const real = collect(candidates.romperCandidates({ words, year: 2024 })).length;
  assert.strictEqual(est, real);
});

test('patternCandidates expande plantillas tipo Palabra_%s_%y', () => {
  const words = ['sol', 'mar'];
  const got = new Set(collect(candidates.patternCandidates('X_%s_%y', { words, year: 2024 })));
  assert.ok(got.has('X_sol_2024'));
  assert.ok(got.has('X_mar_2023'));
});

test('patternCandidates con %n y %D produce dígitos', () => {
  const got = collect(candidates.patternCandidates('pin%n', { words: [] }));
  assert.deepStrictEqual(got, ['pin0', 'pin1', 'pin2', 'pin3', 'pin4', 'pin5', 'pin6', 'pin7', 'pin8', 'pin9']);
  const dd = collect(candidates.patternCandidates('%D', { words: [] }), 3);
  assert.deepStrictEqual(dd, ['00', '01', '02']);
});

test('loadWordlist trata cada línea como literal (sin comentarios)', () => {
  const os = require('os');
  const fs = require('fs');
  const path = require('path');
  const f = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'gz-wl-')), 'wl.txt');
  fs.writeFileSync(f, '#nocomentario\n\nabc\nabc\n');
  const words = candidates.loadWordlist(f);
  assert.deepStrictEqual(words, ['#nocomentario', 'abc']); // vacías fuera, duplicados fuera
});
