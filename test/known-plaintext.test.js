'use strict';

// Catálogo de texto plano por tipo (#1) y recompresión DEFLATE (#2).

const test = require('node:test');
const assert = require('node:assert');
const zlib = require('node:zlib');

const kp = require('../lib/known-plaintext');
const dp = require('../lib/deflate-plain');
const { ATTACK_SIZE } = require('../lib/zipcrypto-attack');

test('extOf saca la extensión del nombre de entrada', () => {
  assert.strictEqual(kp.extOf('disco.vmdk'), 'vmdk');
  assert.strictEqual(kp.extOf('carpeta/MaquinaVirtual.OVA'), 'ova');
  assert.strictEqual(kp.extOf('sin_extension'), '');
});

test('todas las firmas del catálogo tienen ≥12 bytes (mínimo del ataque)', () => {
  for (const s of kp.SIGNATURES) {
    assert.ok(s.bytes.length >= ATTACK_SIZE, `${s.id} tiene ${s.bytes.length} bytes`);
  }
});

test('candidatesForEntry: STORE por extensión de VM', () => {
  const vmdk = kp.candidatesForEntry({ name: 'disk.vmdk', method: 0 });
  assert.ok(vmdk.length >= 1);
  assert.ok(vmdk.some((c) => c.plano.toString('latin1').startsWith('# Disk DescriptorFile')));

  const vdi = kp.candidatesForEntry({ name: 'box.vdi', method: 0 });
  assert.ok(vdi.some((c) => c.plano.toString('latin1').startsWith('<<< Oracle VM VirtualBox')));

  const ova = kp.candidatesForEntry({ name: 'appliance.ova', method: 0 });
  assert.ok(ova.some((c) => c.offset === 512));
});

test('candidatesForEntry: DEFLATE no usa cabeceras en claro (devuelve vacío)', () => {
  assert.deepStrictEqual(kp.candidatesForEntry({ name: 'disk.vmdk', method: 8 }), []);
});

test('candidatesForEntry: extensión desconocida => sin candidatos', () => {
  assert.deepStrictEqual(kp.candidatesForEntry({ name: 'x.desconocido', method: 0 }), []);
});

test('deflateVariants recomprime y una variante casa con el flujo real', () => {
  const contenido = Buffer.from('contenido de un fichero que sí comprime '.repeat(8));
  const real = zlib.deflateRawSync(contenido, { level: 6 });
  const variants = dp.deflateVariants(contenido);
  assert.ok(variants.length >= 2, 'varios niveles');
  assert.ok(
    variants.some((v) => v.data.equals(real)),
    'alguna variante reproduce el deflate real (zlib nivel 6)',
  );
});

test('candidatesFromKnown: STORE => contenido tal cual', () => {
  const known = Buffer.from('hola mundo store');
  const cands = dp.candidatesFromKnown(known, { method: 0 });
  assert.strictEqual(cands.length, 1);
  assert.strictEqual(cands[0].offset, 0);
  assert.ok(cands[0].plano.equals(known));
});

test('candidatesFromKnown: DEFLATE ordena primero la del tamaño coincidente', () => {
  const contenido = Buffer.from('payload comprimible '.repeat(20));
  const real = zlib.deflateRawSync(contenido, { level: 9 });
  const cands = dp.candidatesFromKnown(contenido, { method: 8, compressedSize: real.length });
  assert.ok(cands.length >= 1);
  // El primero debe casar exactamente el flujo real (mismo tamaño y bytes).
  assert.ok(cands[0].plano.equals(real), 'la primera candidata reproduce el flujo comprimido real');
  assert.match(cands[0].etiqueta, /tamaño coincide/);
});

test('candidatesFromKnown: método no soportado lanza', () => {
  assert.throws(() => dp.candidatesFromKnown(Buffer.from('x'), { method: 14 }), /no soportado/);
});

// e2e determinista de la vía DEFLATE (#2): comprime con la MISMA zlib de Node,
// cifra un flujo ZipCrypto a mano y comprueba que, recomprimiendo el fichero
// conocido, una variante casa y el ataque recupera las claves. Lento => gated.
test('e2e: --conocido DEFLATE recupera las claves (recompresión con zlib)', { skip: !process.env.GANZUA_SLOW }, () => {
  const zc = require('../lib/crypto-zipcrypto');
  const attack = require('../lib/zipcrypto-attack');

  // Contenido parcialmente comprimible -> flujo comprimido con bastantes bytes.
  const content = Buffer.alloc(4000);
  for (let i = 0; i < content.length; i++) content[i] = ((i * 7) ^ (i >> 5)) & 0xff;
  const compressed = zlib.deflateRawSync(content, { level: 6 });

  // Construir el flujo cifrado ZipCrypto (12 bytes de cabecera + cuerpo).
  const password = 'clave123';
  const k = new zc.Keys(password);
  const init = [k.k0 >>> 0, k.k1 >>> 0, k.k2 >>> 0];
  const header = Buffer.from('0123456789ab', 'latin1'); // 12 bytes arbitrarios
  const cipher = Buffer.alloc(12 + compressed.length);
  for (let i = 0; i < 12; i++) cipher[i] = k.encryptByte(header[i]);
  for (let i = 0; i < compressed.length; i++) cipher[12 + i] = k.encryptByte(compressed[i]);

  const entry = { method: 8, compressedSize: compressed.length };
  const cands = dp.candidatesFromKnown(content, entry);
  let keys = null;
  for (const c of cands) {
    keys = attack.recoverKeys(cipher, c.plano, c.offset);
    if (keys) break;
  }
  assert.deepStrictEqual(keys, init);
});
