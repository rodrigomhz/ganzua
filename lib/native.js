'use strict';

// Carga opcional del addon N-API (ataque ZipCrypto en C++). Si no está
// compilado (falta compilador o no se ejecutó `npm run build:native`), la
// herramienta sigue funcionando con el motor JS.

let addon = null;
try {
  addon = require('../build/Release/zipcrypto_attack.node');
} catch {
  addon = null;
}

const available = !!(addon && typeof addon.attack === 'function');

// Recupera las claves internas [x,y,z] con el addon C++, o null si no encuentra.
// `jobs` = nº de hilos (0 = todos los núcleos). Lanza si el addon no está.
function attack(ciphertext, plaintext, offsetArg = 0, jobs = 0) {
  if (!available) throw new Error('addon nativo no disponible');
  const k = addon.attack(Buffer.from(ciphertext), Buffer.from(plaintext), offsetArg | 0, jobs | 0);
  return k ? k.map((x) => x >>> 0) : null;
}

module.exports = { available, attack };
