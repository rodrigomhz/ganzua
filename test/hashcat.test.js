'use strict';

const test = require('node:test');
const assert = require('node:assert');

const hashcat = require('../lib/hashcat');
const { runCli, fixturePath } = require('./helpers');

test('isAvailable devuelve un booleano sin lanzar', () => {
  assert.strictEqual(typeof hashcat.isAvailable(), 'boolean');
});

test('buildArgs para diccionario (-a 0) y máscara (-a 3)', () => {
  const wl = hashcat.buildArgs({ attack: 'wordlist', hashFile: '/t/h.txt', source: '/t/w.txt', potFile: '/t/p' });
  assert.deepStrictEqual(wl, ['-m', '13600', '--quiet', '--potfile-path', '/t/p', '-a', '0', '/t/h.txt', '/t/w.txt']);
  const mask = hashcat.buildArgs({ attack: 'mask', hashFile: '/t/h.txt', source: '?l?d?d', potFile: '/t/p' });
  assert.deepStrictEqual(mask, ['-m', '13600', '--quiet', '--potfile-path', '/t/p', '-a', '3', '/t/h.txt', '?l?d?d']);
});

test('showArgs recupera del potfile', () => {
  assert.deepStrictEqual(hashcat.showArgs({ hashFile: '/t/h.txt', potFile: '/t/p' }), [
    '-m',
    '13600',
    '--show',
    '--potfile-path',
    '/t/p',
    '/t/h.txt',
  ]);
});

test('parseShow extrae la contraseña de la línea hash:password', () => {
  const hash = '$zip2$*0*3*0*aabb*1320*e*1964*3135*$/zip2$';
  assert.strictEqual(hashcat.parseShow(`${hash}:Secreto_2024\n`), 'Secreto_2024');
  // La contraseña puede contener ':' — solo se corta en el primero.
  assert.strictEqual(hashcat.parseShow(`${hash}:a:b:c`), 'a:b:c');
  assert.strictEqual(hashcat.parseShow('sin resultados'), null);
  assert.strictEqual(hashcat.parseShow(''), null);
});

test('romper --hashcat recurre al motor propio si hashcat no está', () => {
  // En el entorno de CI/desarrollo hashcat no está instalado: debe avisar por
  // stderr y encontrar la contraseña con el motor propio.
  const { status, stdout, stderr } = runCli(['romper', '--hashcat', '--json', fixturePath('aes256-romper.zip')]);
  if (hashcat.isAvailable()) return; // si hubiera hashcat, este test no aplica
  assert.match(stderr, /hashcat no está en el PATH/);
  const j = JSON.parse(stdout);
  assert.strictEqual(status, 0);
  assert.strictEqual(j.encontrada, true);
  assert.strictEqual(j.contrasena, 'password123');
});
