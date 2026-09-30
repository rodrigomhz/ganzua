'use strict';

const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const { readZip } = require('../lib/zip');
const { safeJoin, extractEntries } = require('../lib/extract');
const { runCli, fixturePath } = require('./helpers');

function tmpDir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'gz-ext-'));
}

test('safeJoin normaliza rutas y bloquea path traversal (zip slip)', () => {
  const base = '/out';
  assert.strictEqual(safeJoin(base, 'a/b.txt'), path.join('/out', 'a', 'b.txt'));
  assert.strictEqual(safeJoin(base, './x.txt'), path.join('/out', 'x.txt'));
  assert.throws(() => safeJoin(base, '../etc/passwd'), /insegura/);
  assert.throws(() => safeJoin(base, 'a/../../etc'), /insegura/);
  assert.throws(() => safeJoin(base, 'a\\..\\..\\b'), /insegura/); // separadores Windows
  // Una ruta absoluta se neutraliza (se le quita la "/" inicial), quedando
  // dentro de baseDir, como hacen las herramientas unzip; no debe escapar.
  assert.strictEqual(safeJoin(base, '/etc/passwd'), path.join('/out', 'etc', 'passwd'));
});

test('extractEntries descifra y escribe con CRC correcto (multi-entrada)', () => {
  const zip = readZip(fixturePath('aes256-multi.zip'));
  const dir = tmpDir();
  const res = extractEntries(zip, zip.entries, { password: 'Comun_2023', outDir: dir });
  assert.strictEqual(res.length, 3);
  assert.ok(res.every((r) => r.ok));
  assert.strictEqual(fs.readFileSync(path.join(dir, 'uno.txt'), 'utf8'), 'primera entrada\n');
  assert.strictEqual(fs.readFileSync(path.join(dir, 'dos.txt'), 'utf8'), 'segunda entrada\n');
});

test('extractEntries rechaza (CRC/inflate) con contraseña incorrecta', () => {
  const zip = readZip(fixturePath('zipcrypto-deflate.zip'));
  const dir = tmpDir();
  const res = extractEntries(zip, zip.entries, { password: 'incorrecta', outDir: dir });
  assert.ok(!res[0].ok, 'no debe extraerse con contraseña incorrecta');
});

test('CLI extrae con contraseña escribe el fichero', () => {
  const dir = tmpDir();
  const { status } = runCli(['extrae', fixturePath('aes256-store.zip'), 'Secreto_2024', '--salida', dir]);
  assert.strictEqual(status, 0);
  assert.strictEqual(
    fs.readFileSync(path.join(dir, 'nota.txt'), 'utf8'),
    'Hola mundo, contenido de prueba para ganzua.\n',
  );
});

test('CLI extrae --json recupera la contraseña y extrae', () => {
  const dir = tmpDir();
  const wl = path.join(tmpDir(), 'wl.txt');
  fs.writeFileSync(wl, 'password123\n');
  const { status, stdout } = runCli([
    'extrae',
    fixturePath('aes256-romper.zip'),
    '--wordlist',
    wl,
    '--salida',
    dir,
    '--json',
  ]);
  const j = JSON.parse(stdout);
  assert.strictEqual(status, 0);
  assert.strictEqual(j.contrasena, 'password123');
  assert.strictEqual(j.extraidas, 1);
  assert.ok(fs.existsSync(path.join(dir, 'privado.txt')));
});

test('CLI extrae falla con contraseña incorrecta', () => {
  const dir = tmpDir();
  const { status } = runCli(['extrae', fixturePath('aes256-store.zip'), 'mala', '--salida', dir]);
  assert.notStrictEqual(status, 0);
});
