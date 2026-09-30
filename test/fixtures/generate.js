'use strict';

// Regenerates the encrypted-ZIP fixtures used by the deterministic tests.
// AES fixtures come from pyzipper; ZipCrypto fixtures from the system `zip`.
// The blind-crack test generates its own random-password archive at runtime
// and does not depend on these files.
//
// Run automatically as the npm `pretest` step.

const { spawnSync } = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');

const outDir = path.join(__dirname, 'out');
fs.mkdirSync(outDir, { recursive: true });

const deflateText = 'ganzua es una herramienta de recuperación de contraseñas ZIP. '.repeat(40);

// --- AES fixtures (pyzipper) ------------------------------------------------

const aesSpecs = [
  {
    file: 'aes256-store.zip',
    entry: 'nota.txt',
    method: 'store',
    nbits: 256,
    password: 'Secreto_2024',
    content: 'Hola mundo, contenido de prueba para ganzua.\n',
  },
  {
    file: 'aes256-deflate.zip',
    entry: 'texto.txt',
    method: 'deflate',
    nbits: 256,
    password: 'Montaña_7',
    content: deflateText,
  },
  {
    // Password reachable by `romper`'s default wordlist+patterns, for a
    // deterministic end-to-end CLI test (raw entry present in the bundled list).
    file: 'aes256-romper.zip',
    entry: 'privado.txt',
    method: 'store',
    nbits: 256,
    password: 'password123',
    content: 'esto lo encuentra romper con los valores por defecto\n',
  },
  {
    file: 'aes128-store.zip',
    entry: 'a128.txt',
    method: 'store',
    nbits: 128,
    password: 'Clave_128',
    content: 'contenido cifrado con AES-128\n',
  },
  {
    file: 'aes192-deflate.zip',
    entry: 'a192.txt',
    method: 'deflate',
    nbits: 192,
    password: 'Clave_192',
    content: deflateText,
  },
  {
    // Varias entradas cifradas con la misma contraseña (caso habitual).
    file: 'aes256-multi.zip',
    method: 'store',
    nbits: 256,
    password: 'Comun_2023',
    entries: [
      { name: 'uno.txt', content: 'primera entrada\n' },
      { name: 'dos.txt', content: 'segunda entrada\n' },
      { name: 'tres.txt', content: 'tercera entrada\n' },
    ],
  },
];

function genAes() {
  const res = spawnSync('python3', [path.join(__dirname, 'gen_aes.py'), outDir, JSON.stringify(aesSpecs)], {
    stdio: 'inherit',
  });
  if (res.status !== 0) {
    console.error('ganzua(fixtures): fallo generando fixtures AES (¿pyzipper instalado?).');
    process.exit(res.status || 1);
  }
}

// --- ZipCrypto fixtures (system `zip`) --------------------------------------

const zcSpecs = [
  {
    file: 'zipcrypto-store.zip',
    entry: 'mensaje.txt',
    store: true,
    password: 'clave123',
    content: 'contenido zipcrypto de prueba\n',
  },
  { file: 'zipcrypto-deflate.zip', entry: 'largo.txt', store: false, password: 'otra_clave', content: deflateText },
];

function genZipCrypto() {
  const zipBin = spawnSync('zip', ['--version'], { stdio: 'ignore' });
  if (zipBin.status !== 0 && zipBin.error) {
    console.error('ganzua(fixtures): no se encontró el comando `zip` del sistema.');
    process.exit(1);
  }
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'ganzua-fix-'));
  for (const s of zcSpecs) {
    const src = path.join(tmp, s.entry);
    fs.writeFileSync(src, s.content);
    const dest = path.join(outDir, s.file);
    fs.rmSync(dest, { force: true });
    const args = ['-q', '-e', '-j'];
    if (s.store) args.push('-0');
    args.push('-P', s.password, dest, src);
    const res = spawnSync('zip', args, { stdio: 'inherit' });
    if (res.status !== 0) {
      console.error(`ganzua(fixtures): fallo generando ${s.file}`);
      process.exit(res.status || 1);
    }
  }
  fs.rmSync(tmp, { recursive: true, force: true });
}

// --- Manifest ---------------------------------------------------------------

function writeManifest() {
  const entries = [
    ...aesSpecs.map((s) => {
      const first = s.entries ? s.entries[0] : { name: s.entry, content: s.content };
      return {
        file: s.file,
        entry: first.name,
        encryption: 'aes',
        method: s.method,
        bits: s.nbits,
        password: s.password,
        content: first.content,
        entries: s.entries ? s.entries.length : 1,
      };
    }),
    ...zcSpecs.map((s) => ({
      file: s.file,
      entry: s.entry,
      encryption: 'zipcrypto',
      method: s.store ? 'store' : 'deflate',
      password: s.password,
      content: s.content,
    })),
  ];
  fs.writeFileSync(path.join(outDir, 'manifest.json'), JSON.stringify(entries, null, 2));
}

genAes();
genZipCrypto();
writeManifest();
console.log(`ganzua(fixtures): ${aesSpecs.length + zcSpecs.length} fixtures en ${outDir}`);
