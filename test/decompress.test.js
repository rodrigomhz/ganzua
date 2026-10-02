'use strict';

// Descompresión del flujo por método: STORE/DEFLATE (Node), BZIP2 (seek-bzip),
// LZMA (lzma-js). Los flujos comprimidos se generan aquí (zlib, bzip2 CLI,
// lzma-js) para no depender de 7z.

const test = require('node:test');
const assert = require('node:assert');
const cp = require('node:child_process');
const zlib = require('node:zlib');

const { decompress } = require('../lib/decompress');
const LZMA = require('lzma');

const PLAIN = Buffer.from('Texto variado para descompresión. Áéíóú ñ. '.repeat(60));

function have(cmd) {
  try {
    cp.execSync(`command -v ${cmd}`, { stdio: 'ignore' });
    return true;
  } catch {
    return false;
  }
}

test('STORE (método 0) devuelve los mismos bytes', async () => {
  const out = await decompress(0, PLAIN, PLAIN.length);
  assert.ok(out.equals(PLAIN));
});

test('DEFLATE (método 8)', async () => {
  const out = await decompress(8, zlib.deflateRawSync(PLAIN), PLAIN.length);
  assert.ok(out.equals(PLAIN));
});

test('BZIP2 (método 12)', { skip: !have('bzip2') }, async () => {
  const comp = cp.execSync('bzip2 -c', { input: PLAIN, maxBuffer: 1e8 });
  const out = await decompress(12, comp, PLAIN.length);
  assert.ok(out.equals(PLAIN));
});

test('LZMA (método 14)', async () => {
  // Comprime a "alone" (.lzma) y reempaqueta al formato LZMA de ZIP.
  const alone = Buffer.from(await new Promise((res, rej) => LZMA.compress(PLAIN, 6, (r, e) => (e ? rej(e) : res(r)))));
  const props = alone.subarray(0, 5);
  const data = alone.subarray(13); // salta 8 bytes de tamaño del formato alone
  const zipLzma = Buffer.concat([Buffer.from([0, 0, 5, 0]), props, data]); // ver(2)+propsSize(2)=5
  const out = await decompress(14, zipLzma, PLAIN.length);
  assert.ok(out.equals(PLAIN));
});

test('un método no soportado (PPMd) lanza un error claro', async () => {
  await assert.rejects(() => decompress(98, Buffer.alloc(4), 10), /no soportada/);
});
