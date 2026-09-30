'use strict';

// Métodos de compresión que 7-Zip puede meter en un .zip (BZIP2, LZMA, …).
// Antes: ZipCrypto+BZip2 daba falso negativo en verifica, y AES/otros métodos
// se "extraían" corruptos. Se prueban con entradas ZipCrypto sintéticas (sin
// depender de 7z, que no está en CI).

const test = require('node:test');
const assert = require('node:assert');
const zlib = require('node:zlib');

const zc = require('../lib/crypto-zipcrypto');
const { verify } = require('../lib/verify');
const { extractEntries } = require('../lib/extract');
const { methodName } = require('../lib/zip');

// Construye una entrada ZipCrypto sintética (bit 3 apagado => check byte = CRC).
function makeZcEntry(password, method, bodyPlain, crc) {
  const keys = new zc.Keys(password);
  const header = Buffer.alloc(12);
  const hp = Buffer.alloc(12);
  for (let i = 0; i < 11; i++) hp[i] = (i * 37) & 0xff;
  hp[11] = (crc >>> 24) & 0xff; // check byte
  for (let i = 0; i < 12; i++) header[i] = keys.encryptByte(hp[i]);
  const body = Buffer.alloc(bodyPlain.length);
  for (let i = 0; i < bodyPlain.length; i++) body[i] = keys.encryptByte(bodyPlain[i]);
  const crypto = { method, flags: 0, crc: crc >>> 0, mtime: 0, header, body };
  return { name: 'x', method, encryption: 'zipcrypto', crypto, dataOffset: 0, compressedSize: body.length + 12 };
}

test('ZipCrypto + BZIP2: verifica por la firma del flujo (no falso negativo)', () => {
  const body = Buffer.from('BZh91AY&SYxxxxxxxx', 'latin1'); // firma bzip2
  const e = makeZcEntry('clave', 12, body, 0x12345678);
  assert.ok(verify(e, 'clave'), 'la contraseña correcta debe validar con BZIP2');
  assert.ok(!verify(e, 'otra'), 'una contraseña incorrecta no debe validar');
});

test('ZipCrypto + LZMA: verifica por la cabecera LZMA en ZIP', () => {
  const body = Buffer.from([0x17, 0x01, 0x05, 0x00, 0x5d, 0x00, 0x10, 0x00, 1, 2, 3, 4]);
  const e = makeZcEntry('clave', 14, body, 0x0badf00d);
  assert.ok(verify(e, 'clave'));
  assert.ok(!verify(e, 'otra'));
});

test('ZipCrypto STORE/DEFLATE sigue confirmando por CRC-32', () => {
  const plain = Buffer.from('contenido store\n');
  const store = makeZcEntry('clave', 0, plain, zc.crc32(plain));
  assert.ok(verify(store, 'clave'));
  const raw = zlib.deflateRawSync(plain);
  const deflate = makeZcEntry('clave', 8, raw, zc.crc32(plain));
  assert.ok(verify(deflate, 'clave'));
});

test('extraer un método no soportado (PPMd) se rechaza sin corromper', () => {
  const e = makeZcEntry('clave', 98, Buffer.from('datos ppmd cualesquiera'), 0x12345678); // 98 = PPMd
  const zip = { buf: Buffer.alloc(0) };
  return extractEntries(zip, [e], { password: 'clave', outDir: require('os').tmpdir() }).then((res) => {
    assert.ok(!res[0].ok);
    assert.match(res[0].error, /98|no soportada/);
  });
});

test('methodName nombra los métodos comunes', () => {
  assert.strictEqual(methodName(0), 'STORE');
  assert.strictEqual(methodName(8), 'DEFLATE');
  assert.strictEqual(methodName(12), 'BZIP2');
  assert.strictEqual(methodName(14), 'LZMA');
  assert.strictEqual(methodName(98), 'PPMd');
  assert.strictEqual(methodName(77), 'método 77');
});
