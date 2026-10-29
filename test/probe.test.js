'use strict';

// Sonda (probe): atacar un ZipCrypto grande compartiendo solo unos KB. Verifica
// el round-trip buildProbe/fromProbe, la validación, el CLI `sonda`, y (gated)
// que atacar la sonda recupera las MISMAS claves que atacar el zip completo.

const test = require('node:test');
const assert = require('node:assert');
const cp = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const { readZip } = require('../lib/zip');
const probeLib = require('../lib/probe');
const { runCli, makeAesZip } = require('./helpers');

const hasPyzipper = (() => {
  try {
    return cp.spawnSync('python3', ['-c', 'import pyzipper']).status === 0;
  } catch {
    return false;
  }
})();

function wordlistWith(dir, password) {
  const w = path.join(dir, 'words.txt');
  fs.writeFileSync(w, ['x', '123456', password, 'y'].join('\n') + '\n');
  return w;
}

const hasZip = (() => {
  try {
    return cp.spawnSync('zip', ['-v']).status === 0;
  } catch {
    return false;
  }
})();
const skipZip = hasZip ? false : 'requiere el comando `zip`';

function makeZipcryptoStore(dir, name, content, password) {
  fs.writeFileSync(path.join(dir, name), content);
  const zipPath = path.join(dir, 'c.zip');
  const r = cp.spawnSync('zip', ['-q', '-0', '-e', '-j', '-P', password, zipPath, path.join(dir, name)]);
  assert.strictEqual(r.status, 0, 'zip debe crear el fixture');
  return zipPath;
}

test('fromProbe rechaza sondas inválidas', () => {
  assert.throws(() => probeLib.fromProbe(null), /sonda no reconocida/);
  assert.throws(() => probeLib.fromProbe({ sonda: 999 }), /sonda no reconocida/);
  // ZipCrypto con cabecera que no mide 12 bytes.
  assert.throws(
    () =>
      probeLib.fromProbe({
        sonda: 1,
        entrada: { cifrado: 'zipcrypto' },
        cabecera_hex: 'aabb',
        cuerpo_prefijo_hex: 'ccdd',
      }),
    /12 bytes/,
  );
  // Cifrado no soportado / ausente.
  assert.throws(() => probeLib.fromProbe({ sonda: 1, entrada: {}, cuerpo_prefijo_hex: 'ccdd' }), /no soportado/);
});

test('buildProbe → fromProbe conserva cabecera y prefijo', { skip: skipZip }, () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'gz-probe-'));
  try {
    const zipPath = makeZipcryptoStore(dir, 'd.bin', Buffer.alloc(500, 7), 'clave-larga-9Z');
    const zip = readZip(zipPath);
    const entry = zip.entries[0];
    const probe = probeLib.buildProbe(zip, entry, { bytes: 64 });
    assert.strictEqual(probe.sonda, probeLib.PROBE_VERSION);
    assert.strictEqual(probe.entrada.cifrado, 'zipcrypto');
    assert.strictEqual(probe.cuerpo_prefijo_bytes, 64);
    assert.strictEqual(Buffer.from(probe.cabecera_hex, 'hex').length, 12);

    const { entry: e2, ciphertext } = probeLib.fromProbe(probe);
    assert.strictEqual(e2.name, entry.name);
    assert.strictEqual(e2.method, entry.method);
    // El ciphertext de la sonda = cabecera + prefijo = primeros 76 bytes del real.
    const real = Buffer.concat([entry.crypto.header, entry.crypto.body]).subarray(0, 12 + 64);
    assert.ok(ciphertext.equals(real));
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('CLI `sonda --json` emite un paquete pequeño y parseable', { skip: skipZip }, () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'gz-probe2-'));
  try {
    const zipPath = makeZipcryptoStore(dir, 'x.bin', Buffer.alloc(300, 9), 'otra-clave-larga-9Z');
    const res = runCli(['sonda', zipPath, '--bytes', '48']);
    assert.strictEqual(res.status, 0);
    const probe = JSON.parse(res.stdout);
    assert.strictEqual(probe.sonda, 1);
    assert.strictEqual(probe.cuerpo_prefijo_bytes, 48);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('romper: recupera la contraseña desde una sonda ZipCrypto DEFLATE', { skip: skipZip }, () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'gz-probe-r1-'));
  try {
    const PASS = 'Examen_Web_2024';
    // Fichero que comprime (DEFLATE) y contraseña cualquiera.
    fs.writeFileSync(
      path.join(dir, 'index.html'),
      '<!DOCTYPE html>\n<html><body>' + 'hola '.repeat(50) + '</body></html>\n',
    );
    const zipPath = path.join(dir, 'web.zip');
    assert.strictEqual(
      cp.spawnSync('zip', ['-q', '-e', '-j', '-P', PASS, zipPath, path.join(dir, 'index.html')]).status,
      0,
    );

    // Sonda con solo 40 B de cuerpo (prefijo DEFLATE).
    const sonda = path.join(dir, 's.json');
    assert.strictEqual(runCli(['sonda', zipPath, '--bytes', '40', '--salida', sonda]).status, 0);

    const res = runCli(['ataca-sonda', sonda, '--romper', '--wordlist', wordlistWith(dir, PASS), '--json']);
    assert.strictEqual(res.status, 0, res.stderr);
    const out = JSON.parse(res.stdout);
    assert.strictEqual(out.encontrada, true);
    assert.strictEqual(out.contrasena, PASS);
    assert.strictEqual(out.cifrado, 'zipcrypto');
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test(
  'romper: recupera la contraseña desde una sonda WinZip AES',
  { skip: hasPyzipper ? false : 'requiere pyzipper' },
  () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'gz-probe-r2-'));
    try {
      const PASS = 'Clave_AES_42';
      const zipPath = makeAesZip({
        dir,
        file: 'aes.zip',
        entry: 'doc.txt',
        content: 'contenido del examen\n',
        password: PASS,
      });
      const sonda = path.join(dir, 's.json');
      assert.strictEqual(runCli(['sonda', zipPath, '--salida', sonda]).status, 0);

      const res = runCli(['ataca-sonda', sonda, '--romper', '--wordlist', wordlistWith(dir, PASS), '--json']);
      assert.strictEqual(res.status, 0, res.stderr);
      const out = JSON.parse(res.stdout);
      assert.strictEqual(out.encontrada, true);
      assert.strictEqual(out.contrasena, PASS);
      assert.strictEqual(out.cifrado, 'aes');
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  },
);

// e2e (lento): atacar SOLO la sonda (cabecera + prefijo) recupera las claves
// internas correctas, idénticas a las que derivan de la contraseña. Usa el
// motor más rápido disponible (nativo si está, si no el JS paralelo).
test('e2e: atacar la sonda recupera las claves correctas', { skip: skipZip || !process.env.GANZUA_SLOW }, async () => {
  const native = require('../lib/native');
  const { recoverKeysParallel } = require('../lib/zipcrypto-attack-parallel');
  const zc = require('../lib/crypto-zipcrypto');

  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'gz-probe3-'));
  try {
    // Contenido de alta entropía (STORE => texto plano = contenido).
    const content = Buffer.alloc(400);
    for (let i = 0; i < content.length; i++) content[i] = (i * 151 + 29) & 0xff;
    const password = 'clave-irrelevante-larga-9Z';
    const zipPath = makeZipcryptoStore(dir, 'k.bin', content, password);
    const zip = readZip(zipPath);
    const entry = zip.entries[0];

    // Sonda con 300 B de cuerpo; texto plano conocido = prefijo del contenido.
    const probe = probeLib.buildProbe(zip, entry, { bytes: 300 });
    const { ciphertext } = probeLib.fromProbe(probe);
    const plano = content.subarray(0, 300);
    const keys = native.available
      ? native.attack(ciphertext, plano, 0, 0)
      : await recoverKeysParallel(ciphertext, plano, 0, {});

    // Las claves recuperadas son el estado inicial derivado de la contraseña.
    const seed = new zc.Keys(password);
    assert.ok(keys, 'debe recuperar claves desde la sonda');
    assert.deepStrictEqual(keys, [seed.k0 >>> 0, seed.k1 >>> 0, seed.k2 >>> 0]);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
