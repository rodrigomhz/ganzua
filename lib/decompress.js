'use strict';

// Descompresión del flujo (ya descifrado) de una entrada ZIP, según su método.
// Soporta STORE, DEFLATE (nativo de Node), BZIP2 (seek-bzip) y LZMA (lzma-js).
// Es asíncrono porque el decodificador LZMA lo es.

const zlib = require('zlib');
const Bunzip = require('seek-bzip');
const LZMA = require('lzma');

// Métodos de compresión descomprimibles.
const SUPPORTED = new Set([0, 8, 12, 14]);

// Reconstruye el contenedor LZMA "alone" (.lzma) a partir del flujo LZMA de ZIP
// (método 14): [versión(2)][propsSize(2)=5][props(5)][datos] ->
// [props(5)][tamaño sin comprimir(8, LE)][datos].
function lzmaAloneFromZip(data, uncompressedSize) {
  const propsSize = data.readUInt16LE(2);
  const props = data.subarray(4, 4 + propsSize);
  const comp = data.subarray(4 + propsSize);
  const size = Buffer.alloc(8);
  size.writeUInt32LE(uncompressedSize >>> 0, 0);
  size.writeUInt32LE(Math.floor(uncompressedSize / 2 ** 32), 4);
  return Buffer.concat([props, size, comp]);
}

function lzmaDecompress(alone) {
  return new Promise((resolve, reject) => {
    LZMA.decompress(alone, (result, err) => {
      if (err) return reject(err instanceof Error ? err : new Error(String(err)));
      resolve(Buffer.from(result));
    });
  });
}

// Descomprime `data` (bytes ya descifrados) del método dado. `uncompressedSize`
// viene del directorio central (necesario para LZMA). Devuelve un Buffer.
async function decompress(method, data, uncompressedSize) {
  switch (method) {
    case 0:
      return Buffer.from(data);
    case 8:
      return zlib.inflateRawSync(data);
    case 12:
      return Buffer.from(Bunzip.decode(data));
    case 14:
      return lzmaDecompress(lzmaAloneFromZip(data, uncompressedSize));
    default:
      throw new Error(
        `compresión ${method} no soportada (ganzua descomprime STORE/DEFLATE/BZIP2/LZMA; ` +
          'para PPMd u otros usa 7z/unzip tras recuperar la contraseña)',
      );
  }
}

module.exports = { decompress, SUPPORTED, lzmaAloneFromZip };
