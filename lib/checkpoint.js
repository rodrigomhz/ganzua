'use strict';

// Persistencia de progreso para búsquedas largas. El flujo de candidatas es
// determinista para una configuración dada, así que basta con guardar cuántas
// candidatas se han consumido (la "posición") y reanudar saltando esas.

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const VERSION = 1;

// Firma de la configuración de búsqueda: si cambia, el checkpoint no aplica.
function signature(archivo, entrada, opts) {
  const cfg = {
    archivo: path.resolve(archivo),
    entrada,
    wordlist: opts.wordlist ? path.resolve(opts.wordlist) : 'bundled',
    patron: opts.patron || null,
    mascara: opts.mascara || null,
    agresivo: !!opts.agresivo,
  };
  // Candidatas de la IA (no deterministas): forman parte de la configuración.
  // Solo se añade si las hay, para no invalidar checkpoints sin IA.
  if (opts.iaWords) cfg.ia = crypto.createHash('sha256').update(JSON.stringify(opts.iaWords)).digest('hex');
  return crypto.createHash('sha256').update(JSON.stringify(cfg)).digest('hex').slice(0, 16);
}

function load(file) {
  try {
    const obj = JSON.parse(fs.readFileSync(file, 'utf8'));
    if (obj && obj.version === VERSION) return obj;
  } catch {
    /* sin checkpoint válido */
  }
  return null;
}

// `ia`: lista de candidatas de la IA, guardada para reutilizarla al reanudar.
function save(file, { firma, archivo, entrada, position, total, ia }) {
  const obj = { version: VERSION, firma, archivo, entrada, position, total, ts: new Date().toISOString() };
  if (ia) obj.ia = ia;
  fs.writeFileSync(file, JSON.stringify(obj));
}

function remove(file) {
  try {
    fs.unlinkSync(file);
  } catch {
    /* no existía */
  }
}

module.exports = { VERSION, signature, load, save, remove };
