'use strict';

const test = require('node:test');
const assert = require('node:assert');

const { runCli, fixturePath } = require('./helpers');

test('--version imprime la versión', () => {
  const { status, stdout } = runCli(['--version']);
  assert.strictEqual(status, 0);
  assert.match(stdout, /^ganzua \d+\.\d+\.\d+/);
});

test('--help muestra `romper` como comando principal', () => {
  const { status, stdout } = runCli(['--help']);
  assert.strictEqual(status, 0);
  assert.match(stdout, /COMANDO PRINCIPAL/);
  // romper debe aparecer antes que los comandos de apoyo
  assert.ok(stdout.indexOf('romper') < stdout.indexOf('analiza'), 'romper va primero');
  assert.match(stdout, /autorizad/i); // aviso de uso autorizado
});

test('verifica devuelve 0/1 según la contraseña', () => {
  const ok = runCli(['verifica', fixturePath('aes256-store.zip'), 'Secreto_2024']);
  assert.strictEqual(ok.status, 0);
  const bad = runCli(['verifica', fixturePath('aes256-store.zip'), 'no']);
  assert.strictEqual(bad.status, 1);
});

test('analiza --json describe las entradas', () => {
  const { status, stdout } = runCli(['analiza', '--json', fixturePath('aes256-store.zip')]);
  assert.strictEqual(status, 0);
  const j = JSON.parse(stdout);
  assert.strictEqual(j.entradas[0].cifrado, 'aes');
  assert.strictEqual(j.entradas[0].aes.fuerza_bits, 256);
});

test('material emite un hash $zip2$ para hashcat', () => {
  const { status, stdout } = runCli(['material', fixturePath('aes256-store.zip')]);
  assert.strictEqual(status, 0);
  assert.match(stdout.trim(), /^\$zip2\$\*0\*3\*0\*[0-9a-f]{32}\*[0-9a-f]{4}\*.*\*\$\/zip2\$$/);
});

test('material rechaza entradas ZipCrypto', () => {
  const { status, stderr } = runCli(['material', fixturePath('zipcrypto-store.zip')]);
  assert.notStrictEqual(status, 0);
  assert.match(stderr, /13600|AES/);
});

test('romper encuentra una contraseña por defecto (fixture determinista)', () => {
  const { status, stdout } = runCli(['romper', '--json', fixturePath('aes256-romper.zip')]);
  const j = JSON.parse(stdout);
  assert.strictEqual(status, 0);
  assert.strictEqual(j.encontrada, true);
  assert.strictEqual(j.contrasena, 'password123');
});

test('romper informa qué probar cuando falla', () => {
  // Limitamos a pocas candidatas con una wordlist que no contiene la clave.
  const os = require('os');
  const fs = require('fs');
  const path = require('path');
  const wl = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'gz-wl-')), 'wl.txt');
  fs.writeFileSync(wl, 'aaa\nbbb\n');
  const { status, stderr } = runCli(['romper', '--wordlist', wl, fixturePath('aes256-store.zip')]);
  assert.strictEqual(status, 1);
  assert.match(stderr, /--agresivo/);
  assert.match(stderr, /--wordlist/);
});

test('analiza lista todas las entradas de un ZIP multi-entrada', () => {
  const { status, stdout } = runCli(['analiza', '--json', fixturePath('aes256-multi.zip')]);
  const j = JSON.parse(stdout);
  assert.strictEqual(status, 0);
  assert.strictEqual(j.entradas.length, 3);
  assert.deepStrictEqual(
    j.entradas.map((e) => e.nombre),
    ['uno.txt', 'dos.txt', 'tres.txt']
  );
});

test('verifica --todas exige que la clave abra todas las entradas', () => {
  const ok = runCli(['verifica', '--todas', '--json', fixturePath('aes256-multi.zip'), 'Comun_2023']);
  const j = JSON.parse(ok.stdout);
  assert.strictEqual(ok.status, 0);
  assert.strictEqual(j.valida_todas, true);
  assert.strictEqual(j.entradas.length, 3);

  const bad = runCli(['verifica', '--todas', fixturePath('aes256-multi.zip'), 'no']);
  assert.strictEqual(bad.status, 1);
});

test('material --todas emite un hash por entrada AES', () => {
  const { status, stdout } = runCli(['material', '--todas', fixturePath('aes256-multi.zip')]);
  assert.strictEqual(status, 0);
  const lines = stdout.trim().split('\n');
  assert.strictEqual(lines.length, 3);
  for (const l of lines) assert.match(l, /^\$zip2\$/);
});

test('--entrada N selecciona una entrada concreta', () => {
  const { status, stdout } = runCli(['verifica', '--entrada', '2', '--json', fixturePath('aes256-multi.zip'), 'Comun_2023']);
  const j = JSON.parse(stdout);
  assert.strictEqual(status, 0);
  assert.strictEqual(j.entrada.indice, 2);
  assert.strictEqual(j.entrada.nombre, 'tres.txt');
  assert.strictEqual(j.valida, true);
});

test('romper informa qué entradas abre la contraseña (campo abre)', () => {
  // Ataca la entrada 0 con una wordlist que contiene la clave; debe reportar
  // que abre las 3 entradas (misma contraseña).
  const os = require('os');
  const fs = require('fs');
  const path = require('path');
  const wl = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'gz-wl-')), 'wl.txt');
  fs.writeFileSync(wl, 'Comun_2023\n');
  const { status, stdout } = runCli(['romper', '--json', '--wordlist', wl, fixturePath('aes256-multi.zip')]);
  const j = JSON.parse(stdout);
  assert.strictEqual(status, 0);
  assert.strictEqual(j.encontrada, true);
  assert.strictEqual(j.abre.length, 3);
});

test('comando desconocido falla con ayuda', () => {
  const { status, stderr } = runCli(['inventado']);
  assert.notStrictEqual(status, 0);
  assert.match(stderr, /desconocido/);
});
