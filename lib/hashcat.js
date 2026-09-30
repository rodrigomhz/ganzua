'use strict';

// Integración opcional con hashcat: si está en el PATH, `romper --hashcat`
// delega en él (modo 13600, WinZip AES) usando el hash $zip2$ que produce
// `material`. Si no está disponible, el llamador vuelve al motor propio.
//
// Las piezas puras (detección, construcción de argumentos, parseo de --show)
// son testeables sin hashcat instalado; la orquestación se apoya en ellas.

const { spawnSync } = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');

const MODE = 13600;

// ¿Está hashcat en el PATH?
function isAvailable() {
  try {
    const res = spawnSync('hashcat', ['--version'], { stdio: 'ignore', timeout: 10000 });
    return res.status === 0;
  } catch {
    return false;
  }
}

// Argumentos para lanzar el ataque.
//   attack: 'wordlist' (-a 0) usa `source` como fichero de diccionario
//           'mask'     (-a 3) usa `source` como máscara
function buildArgs({ attack, hashFile, source, potFile }) {
  const base = ['-m', String(MODE), '--quiet', '--potfile-path', potFile];
  if (attack === 'mask') return [...base, '-a', '3', hashFile, source];
  return [...base, '-a', '0', hashFile, source];
}

// Argumentos para recuperar el resultado ya crackeado del potfile.
function showArgs({ hashFile, potFile }) {
  return ['-m', String(MODE), '--show', '--potfile-path', potFile, hashFile];
}

// Parsea la salida de `--show` (líneas "hash:password") y devuelve la
// contraseña, o null si no hay ninguna. El hash $zip2$ no contiene ':', así que
// la contraseña es todo lo que sigue al primer ':'.
function parseShow(stdout) {
  for (const line of stdout.split('\n')) {
    const trimmed = line.replace(/\r$/, '');
    if (!trimmed.startsWith('$zip2$')) continue;
    const idx = trimmed.indexOf(':');
    if (idx >= 0) return trimmed.slice(idx + 1);
  }
  return null;
}

// Ejecuta hashcat contra un hash $zip2$. `source` es un fichero de diccionario
// (attack 'wordlist') o una máscara (attack 'mask').
// Devuelve { found, password }.
function run({ hash, attack, source, extraArgs = [] }) {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'ganzua-hc-'));
  const hashFile = path.join(tmp, 'hash.txt');
  const potFile = path.join(tmp, 'ganzua.potfile');
  fs.writeFileSync(hashFile, hash + '\n');
  try {
    const args = [...buildArgs({ attack, hashFile, source, potFile }), ...extraArgs];
    // status 0 = crackeado, 1 = agotado sin encontrar; ambos son ejecuciones OK.
    spawnSync('hashcat', args, { encoding: 'utf8' });
    const show = spawnSync('hashcat', showArgs({ hashFile, potFile }), { encoding: 'utf8' });
    const password = parseShow(show.stdout || '');
    return { found: password !== null, password };
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
}

module.exports = { MODE, isAvailable, buildArgs, showArgs, parseShow, run };
