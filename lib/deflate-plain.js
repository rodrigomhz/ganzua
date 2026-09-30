'use strict';

// Texto plano conocido para entradas DEFLATE (#2). El cifrado ZipCrypto va
// sobre el flujo YA COMPRIMIDO, así que para atacar una entrada DEFLATE no vale
// el contenido en claro: hay que recomprimirlo igual que lo hizo el archivador.
// No sabemos qué nivel usó, así que probamos varios (0..9) y devolvemos cada
// flujo deflate crudo como candidato de texto plano. Funciona cuando el
// archivador usó un deflate compatible con zlib (lo habitual); 7-Zip e Info-ZIP
// pueden divergir, y entonces hace falta una copia exacta del flujo comprimido.
//
// Para entradas STORE el "candidato" es el propio contenido conocido.

const zlib = require('zlib');

const DEFAULT_LEVELS = [6, 9, 1, 8, 7, 5, 4, 3, 2, 0];

// Variantes deflate crudas del contenido conocido, deduplicadas por bytes.
// Devuelve [{ nivel, data }].
function deflateVariants(known, { levels = DEFAULT_LEVELS } = {}) {
  const out = [];
  const seen = new Set();
  for (const level of levels) {
    let data;
    try {
      data = zlib.deflateRawSync(known, { level });
    } catch {
      continue;
    }
    const key = data.toString('latin1');
    if (seen.has(key)) continue;
    seen.add(key);
    out.push({ nivel: level, data });
  }
  return out;
}

// Candidatos de texto plano a partir de un fichero conocido SIN comprimir,
// adaptados al método de la entrada:
//   STORE (0)   -> el propio contenido conocido (offset 0),
//   DEFLATE (8) -> recompresiones a varios niveles; primero las cuyo tamaño
//                  coincide con el comprimido real (señal fuerte de que casan).
// Devuelve [{ etiqueta, offset, plano }] o lanza si el método no es abordable.
function candidatesFromKnown(known, entry) {
  if (entry.method === 0) {
    return [{ etiqueta: 'contenido conocido (STORE)', offset: 0, plano: known }];
  }
  if (entry.method === 8) {
    const variants = deflateVariants(known);
    const cands = variants.map((v) => ({
      etiqueta: `deflate nivel ${v.nivel}${v.data.length === entry.compressedSize ? ' · tamaño coincide' : ''}`,
      offset: 0,
      plano: v.data,
      _match: v.data.length === entry.compressedSize,
    }));
    // Primero las que igualan el tamaño comprimido real (casan el flujo entero).
    cands.sort((a, b) => Number(b._match) - Number(a._match));
    return cands.map(({ etiqueta, offset, plano }) => ({ etiqueta, offset, plano }));
  }
  throw new Error(`método ${entry.method} no soportado por texto plano (usa STORE o DEFLATE)`);
}

module.exports = { deflateVariants, candidatesFromKnown, DEFAULT_LEVELS };
