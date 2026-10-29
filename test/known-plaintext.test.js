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

test('candidatesForEntry: ficheros web (html/svg) por extensión', () => {
  const html = kp.candidatesForEntry({ name: 'index.html', method: 0 });
  assert.ok(html.some((c) => c.plano.toString('latin1') === '<!DOCTYPE html>'));
  assert.ok(html.some((c) => c.plano.toString('latin1') === '<!doctype html>'));

  const svg = kp.candidatesForEntry({ name: 'logo.svg', method: 0 });
  assert.ok(svg.some((c) => c.plano.toString('latin1').startsWith('<svg xmlns=')));
  assert.ok(svg.some((c) => c.plano.toString('latin1').startsWith('<?xml')));
});

test('candidatesForEntry: de más a menos bytes (lo más rápido primero)', () => {
  const svg = kp.candidatesForEntry({ name: 'logo.svg', method: 0 });
  assert.ok(svg.length >= 2);
  for (let i = 1; i < svg.length; i++) assert.ok(svg[i - 1].plano.length >= svg[i].plano.length);
});

test('autoPlan: la entrada con más texto plano conocido va primero', () => {
  const zc = (name, method, compressedSize, index) => ({
    index,
    name,
    method,
    encryption: 'zipcrypto',
    compressedSize,
  });
  const plan = kp.autoPlan([
    zc('index.html', 0, 500, 0),
    zc('logo.svg', 0, 300, 1),
    zc('app.js', 8, 300, 2),
    { index: 3, name: 'leeme.txt', method: 0, encryption: 'none', compressedSize: 30 },
    zc('mini.svg', 0, 12 + 20, 4), // cuerpo de 20 B: solo caben firmas cortas
  ]);
  assert.strictEqual(plan[0].entry.name, 'logo.svg');
  assert.ok(plan[0].plano.toString('latin1').startsWith('<svg xmlns='));
  assert.ok(plan.some((c) => c.entry.name === 'index.html'));
  assert.ok(!plan.some((c) => c.entry.name === 'app.js'), 'DEFLATE no usa cabeceras en claro');
  assert.ok(!plan.some((c) => c.entry.name === 'leeme.txt'), 'sin cifrar no se ataca');
  const mini = plan.filter((c) => c.entry.name === 'mini.svg');
  assert.ok(mini.length >= 1 && mini.every((c) => c.offset + c.plano.length <= 20));
  for (let i = 1; i < plan.length; i++) assert.ok(plan[i - 1].plano.length >= plan[i].plano.length);
});

test('withCheckByte: antepone el check byte en offset -1 (CRC, o la hora con bit 3)', () => {
  const cand = { etiqueta: 'x', offset: 0, plano: Buffer.from('<!DOCTYPE html>') };
  const crc = kp.withCheckByte(cand, { flags: 0, crc: 0xab123456, mtime: 0x1234 });
  assert.strictEqual(crc.offset, -1);
  assert.strictEqual(crc.plano.length, cand.plano.length + 1);
  assert.strictEqual(crc.plano[0], 0xab, 'byte alto del CRC');
  assert.ok(crc.plano.subarray(1).equals(cand.plano));
  const dd = kp.withCheckByte(cand, { flags: 0x08, crc: 0xab123456, mtime: 0x9a12 });
  assert.strictEqual(dd.plano[0], 0x9a, 'byte alto de la hora (data descriptor)');
  const lejos = { ...cand, offset: 512 };
  assert.strictEqual(kp.withCheckByte(lejos, { flags: 0, crc: 0 }), lejos, 'solo si empieza en el offset 0');
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
