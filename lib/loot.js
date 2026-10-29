'use strict';

// "Botín sin contraseña": clasifica qué se puede obtener de un ZIP SIN
// contraseña ni descifrado, y lo rescata. Dos vías, ninguna descifra nada:
//   1. entradas SIN cifrar  -> se leen (y descomprimen) directamente,
//   2. entradas pequeñas con CRC-32 en claro -> se reconstruye el contenido
//      por fuerza bruta del texto plano contra ese CRC (ver lib/crc-recover).

const fs = require('fs');
const path = require('path');

const { crcLeaked, searchSpace, charsetBytes, recoverByCrc, DEFAULT_MAX_SPACE } = require('./crc-recover');
const { safeJoin, plaintext } = require('./extract');

// Clasifica cómo se obtiene una entrada sin contraseña:
//   'directorio' carpeta (sin contenido)
//   'plano'      sin cifrar: lectura directa
//   'vacio'      0 bytes: contenido vacío conocido
//   'crc'        cifrada pero reconstruible desde el CRC-32 (tamaño pequeño)
//   'ninguno'    requiere descifrar (incluye `motivo`)
function classify(entry, opts = {}) {
  if (entry.name.endsWith('/')) return { modo: 'directorio' };
  if (entry.encryption === 'none') return { modo: 'plano' };
  if (entry.uncompressedSize === 0) return { modo: 'vacio' };

  if (!crcLeaked(entry)) {
    const motivo = entry.encryption === 'aes' ? 'WinZip AES AE-2 no expone el CRC' : 'sin CRC en claro';
    return { modo: 'ninguno', motivo };
  }

  const charset = opts.charsetBytes || charsetBytes(opts.charset);
  const maxSpace = opts.maxSpace == null ? DEFAULT_MAX_SPACE : opts.maxSpace;
  if (opts.maxBytes != null && entry.uncompressedSize > opts.maxBytes) {
    return { modo: 'ninguno', motivo: `${entry.uncompressedSize} B supera --maxbytes (${opts.maxBytes})` };
  }
  const space = searchSpace(charset.length, entry.uncompressedSize);
  if (!Number.isFinite(space) || space > maxSpace) {
    return { modo: 'ninguno', motivo: `${entry.uncompressedSize} B: espacio de búsqueda inabordable por CRC` };
  }
  return { modo: 'crc', espacio: space };
}

// Rescata (sin contraseña) las entradas dadas a outDir. Devuelve un informe por
// entrada análogo a extractEntries. Nunca descifra: 'plano'/'vacio' se leen y
// 'crc' se reconstruye desde el CRC-32.
async function rescue(zip, entries, opts = {}) {
  const { outDir, maxSpace, maxBytes, onFile, onCrc, onProgress } = opts;
  const cset = opts.charsetBytes || charsetBytes(opts.charset);
  const results = [];

  for (const entry of entries) {
    const info = classify(entry, { charsetBytes: cset, maxSpace, maxBytes });
    let dest;
    try {
      dest = safeJoin(outDir, entry.name);
    } catch (err) {
      results.push({ nombre: entry.name, modo: info.modo, ok: false, error: err.message });
      continue;
    }

    try {
      if (info.modo === 'directorio') {
        fs.mkdirSync(dest, { recursive: true });
        results.push({ nombre: entry.name, modo: 'directorio', ruta: dest, ok: true, directorio: true });
        continue;
      }
      if (info.modo === 'ninguno') {
        results.push({ nombre: entry.name, modo: 'ninguno', ok: false, error: info.motivo });
        continue;
      }

      let content;
      if (info.modo === 'plano') {
        content = await plaintext(entry, zip, {}); // sin password ni keys
      } else if (info.modo === 'vacio') {
        content = Buffer.alloc(0);
      } else {
        // 'crc': reconstrucción del contenido en claro desde el CRC-32.
        if (onCrc) onCrc(entry, info);
        content = recoverByCrc(entry.crc >>> 0, entry.uncompressedSize, {
          charsetBytes: cset,
          maxSpace,
          onProgress,
        });
        if (!content) {
          results.push({ nombre: entry.name, modo: 'crc', ok: false, error: 'ningún contenido casa con el CRC-32' });
          continue;
        }
      }

      fs.mkdirSync(path.dirname(dest), { recursive: true });
      fs.writeFileSync(dest, content);
      results.push({ nombre: entry.name, modo: info.modo, ruta: dest, ok: true, bytes: content.length });
      if (onFile) onFile(entry.name, dest, content.length, info.modo);
    } catch (err) {
      results.push({ nombre: entry.name, modo: info.modo, ok: false, error: err.message });
    }
  }
  return results;
}

module.exports = { classify, rescue };
