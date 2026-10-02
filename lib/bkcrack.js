'use strict';

// Integración opcional con bkcrack para el ataque de texto plano conocido
// contra ZipCrypto (Biham-Kocher). Si bkcrack está en el PATH, recupera las
// claves internas a partir de ~12 bytes de texto plano conocido; ganzua luego
// descifra y extrae TODO el archivo con esas claves, sin la contraseña.
//
// Piezas puras (detección, argumentos, parseo de claves) testeables sin
// bkcrack instalado.

const { spawnSync } = require('child_process');

function isAvailable() {
  try {
    const res = spawnSync('bkcrack', ['--version'], { stdio: 'ignore', timeout: 10000 });
    // bkcrack devuelve 0 con --version en versiones recientes; algunas imprimen
    // la ayuda con código !=0, así que aceptamos también que el binario exista.
    return res.status === 0 || (res.error === undefined && res.status !== null);
  } catch {
    return false;
  }
}

// Argumentos para bkcrack. Modos de texto plano:
//   { zip, entry, plainFile }         -> -C <zip> -c <entry> -p <plainFile>
//   { zip, entry, offset, hex }       -> -C <zip> -c <entry> -x <offset> <hex>
function buildArgs({ zip, entry, plainFile, offset, hex }) {
  const args = ['-C', zip, '-c', entry];
  if (plainFile) args.push('-p', plainFile);
  else if (hex) args.push('-x', String(offset || 0), hex);
  return args;
}

// Parsea las 3 claves internas (k0 k1 k2) de la salida de bkcrack. bkcrack
// imprime, tras "Keys", una línea con tres enteros hexadecimales de 8 dígitos.
function parseKeys(stdout) {
  const re = /\b([0-9a-fA-F]{8})\s+([0-9a-fA-F]{8})\s+([0-9a-fA-F]{8})\b/;
  for (const line of stdout.split('\n')) {
    const m = line.match(re);
    if (m) return [parseInt(m[1], 16) >>> 0, parseInt(m[2], 16) >>> 0, parseInt(m[3], 16) >>> 0];
  }
  return null;
}

// Ejecuta bkcrack y devuelve las claves internas, o null si no las recupera.
function run(spec) {
  const res = spawnSync('bkcrack', buildArgs(spec), { encoding: 'utf8' });
  return parseKeys((res.stdout || '') + '\n' + (res.stderr || ''));
}

module.exports = { isAvailable, buildArgs, parseKeys, run };
