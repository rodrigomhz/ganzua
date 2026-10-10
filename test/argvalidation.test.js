'use strict';

// Validación de opciones numéricas: un valor no entero (p. ej. --entrada abc)
// debe dar un error claro en vez de convertirse en NaN silenciosamente.

const test = require('node:test');
const assert = require('node:assert');

const { runCli, fixturePath } = require('./helpers');

const ZIP = fixturePath('zipcrypto-store.zip');

test('--entrada no numérico falla con mensaje claro', () => {
  const res = runCli(['analiza', ZIP, '--entrada', 'abc']);
  assert.notStrictEqual(res.status, 0);
  assert.match(res.stderr, /--entrada debe ser un número entero/);
});

test('--hilos negativo falla (no negativo)', () => {
  const res = runCli(['romper', ZIP, '--hilos', '-2']);
  assert.notStrictEqual(res.status, 0);
  assert.match(res.stderr, /--hilos debe ser un número entero no negativo/);
});

test('--offset sí admite negativos', () => {
  // -5 es un offset válido; el error, si lo hubiera, no debe ser de validación.
  const res = runCli(['analiza', ZIP, '--offset', '-5']);
  assert.doesNotMatch(res.stderr || '', /--offset debe ser/);
});

test('un valor numérico válido pasa la validación', () => {
  const res = runCli(['analiza', ZIP, '--entrada', '0']);
  assert.strictEqual(res.status, 0);
});
