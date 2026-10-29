'use strict';

// LÍNEA ROJA del proyecto.
//
// En cada ejecución se genera una contraseña ALEATORIA nueva, se crea un ZIP
// cifrado con ella y se comprueba que `ganzua romper` la encuentra SIN que se
// le diga cuál es. Si esto se rompe, es una regresión grave: significa que la
// herramienta ya no cumple su función principal (romper el ZIP sin conocer la
// contraseña).
//
// La contraseña se construye a partir de los MISMOS patrones documentados que
// `romper` genera por defecto (palabra tal cual, capitalizada, palabra+sufijo,
// mayúscula+número, palabra+año, mayúscula+año), de modo que la prueba valida
// de extremo a extremo: generador de candidatas + criptografía AES + CLI.

const test = require('node:test');
const assert = require('node:assert');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const candidates = require('../lib/candidates');
const { makeAesZip, runCli } = require('./helpers');

const YEAR = new Date().getFullYear();
const OPTS = candidates.buildOptions({ year: YEAR }); // rangos por defecto
const cap = candidates.capitalize;

function pick(arr) {
  return arr[crypto.randomInt(arr.length)];
}

// Devuelve una contraseña aleatoria construida con un patrón por defecto.
function randomPassword(words) {
  const w = pick(words);
  const suffix = pick(OPTS.suffixes);
  const year = pick(OPTS.years);
  const patterns = [
    () => w,
    () => cap(w),
    () => w + suffix,
    () => cap(w) + suffix,
    () => w + year,
    () => cap(w) + year,
  ];
  return pick(patterns)();
}

test('romper encuentra una contraseña aleatoria fresca (wordlist a medida)', () => {
  const bundled = candidates.loadBundledWordlist();
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'ganzua-blind-'));

  for (let i = 0; i < 5; i++) {
    // Wordlist pequeña y aleatoria (para que la búsqueda sea rápida) que
    // contiene la palabra base.
    const base = pick(bundled);
    const others = new Set([base]);
    while (others.size < 6) others.add(pick(bundled));
    const words = [...others];
    const wlFile = path.join(tmp, `wl-${i}.txt`);
    fs.writeFileSync(wlFile, words.join('\n') + '\n');

    const password = randomPassword([base]);
    const zip = makeAesZip({ dir: tmp, file: `blind-${i}.zip`, password });

    const { status, stdout } = runCli(['romper', '--json', '--wordlist', wlFile, zip]);
    const info = JSON.parse(stdout);
    assert.strictEqual(status, 0, `romper debió tener éxito para «${password}»`);
    assert.strictEqual(info.encontrada, true, `no encontró «${password}»`);
    assert.strictEqual(info.contrasena, password, 'la contraseña recuperada debe coincidir');
  }

  fs.rmSync(tmp, { recursive: true, force: true });
});

test('romper con la wordlist incluida por defecto (sin --wordlist)', () => {
  // Palabra base entre las primeras de la lista incluida + patrón rápido, para
  // que la ejecución por defecto (sin --wordlist) termine en poco tiempo.
  const bundled = candidates.loadBundledWordlist();
  const base = bundled[crypto.randomInt(15)];
  const suffix = pick(OPTS.suffixes);
  const password = base + suffix; // palabra+sufijo, patrón por defecto
  const zip = makeAesZip({ password });

  const { status, stdout } = runCli(['romper', '--json', zip]);
  const info = JSON.parse(stdout);
  assert.strictEqual(status, 0);
  assert.strictEqual(info.encontrada, true, `no encontró «${password}» con los valores por defecto`);
  assert.strictEqual(info.contrasena, password);

  fs.rmSync(path.dirname(zip), { recursive: true, force: true });
});
