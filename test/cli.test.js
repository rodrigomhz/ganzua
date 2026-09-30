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

test('comando desconocido falla con ayuda', () => {
  const { status, stderr } = runCli(['inventado']);
  assert.notStrictEqual(status, 0);
  assert.match(stderr, /desconocido/);
});
