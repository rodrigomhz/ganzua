'use strict';

// Recuperación de contenido por CRC-32 sin descifrar. Verifica que, dado el
// CRC-32 que el ZIP almacena en claro, se reconstruye el contenido de entradas
// pequeñas; que los alfabetos restringen el espacio; y que un espacio enorme se
// rechaza en vez de colgarse.

const test = require('node:test');
const assert = require('node:assert');

const { crc32 } = require('../lib/crypto-zipcrypto');
const cr = require('../lib/crc-recover');

test('recupera contenido de 1..3 bytes (los 256 valores) por su CRC-32', () => {
  for (const s of ['A', 'Zx', 'PIN']) {
    const buf = Buffer.from(s, 'latin1');
    const got = cr.recoverByCrc(crc32(buf), buf.length);
    assert.ok(got, `debe recuperar «${s}»`);
    assert.strictEqual(got.toString('latin1'), s);
  }
});

test('tamaño 0 => contenido vacío cuando CRC=0', () => {
  const got = cr.recoverByCrc(0, 0);
  assert.ok(got);
  assert.strictEqual(got.length, 0);
});

test('tamaño 0 con CRC≠0 no tiene solución', () => {
  assert.strictEqual(cr.recoverByCrc(0x12345678, 0), null);
});

test('un CRC que no corresponde a ninguna combinación devuelve null', () => {
  // Espacio 1 byte (256) — elegimos un CRC imposible para longitud 1.
  // El CRC de cualquier byte único es conocido; usamos un valor que no aparece.
  const seen = new Set();
  for (let b = 0; b < 256; b++) seen.add(crc32(Buffer.from([b])));
  let bogus = 1;
  while (seen.has(bogus >>> 0)) bogus++;
  assert.strictEqual(cr.recoverByCrc(bogus, 1), null);
});

test('un alfabeto restringido recupera tamaños mayores (dígitos, 5 cifras)', () => {
  const buf = Buffer.from('90210', 'latin1');
  const got = cr.recoverByCrc(crc32(buf), buf.length, { charset: 'digits' });
  assert.ok(got);
  assert.strictEqual(got.toString('latin1'), '90210');
});

test('los presets de alfabeto existen y no tienen bytes duplicados', () => {
  for (const name of ['digits', 'lower', 'upper', 'alnum', 'hex', 'print']) {
    const bytes = cr.charsetBytes(name);
    assert.ok(bytes.length > 0, `${name} no vacío`);
    assert.strictEqual(new Set(bytes).size, bytes.length, `${name} sin duplicados`);
  }
  assert.strictEqual(cr.charsetBytes('bytes').length, 256);
});

test('un espacio de búsqueda demasiado grande se rechaza (no se cuelga)', () => {
  // 4 bytes con los 256 valores = 2^32 > límite por defecto.
  assert.throws(
    () => cr.recoverByCrc(0, 4),
    (err) => err.code === 'SPACE_TOO_LARGE',
  );
  // Subiendo maxSpace y con alfabeto pequeño sí procede.
  const buf = Buffer.from('ab', 'latin1');
  assert.ok(cr.recoverByCrc(crc32(buf), 2, { charset: 'lower' }));
});

test('crcLeaked: ZipCrypto y sin cifrar sí; AES depende de AE-1/AE-2', () => {
  assert.strictEqual(cr.crcLeaked({ encryption: 'none' }), true);
  assert.strictEqual(cr.crcLeaked({ encryption: 'zipcrypto' }), true);
  assert.strictEqual(cr.crcLeaked({ encryption: 'aes', aes: { version: 1 } }), true);
  assert.strictEqual(cr.crcLeaked({ encryption: 'aes', aes: { version: 2 } }), false);
  assert.strictEqual(cr.crcLeaked({ encryption: 'aes', aes: null }), false);
});
