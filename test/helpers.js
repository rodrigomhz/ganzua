'use strict';

// Test helpers: mint encrypted ZIPs on demand (used by the blind-crack test),
// and load the deterministic fixture manifest.

const { spawn, spawnSync } = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');

const FIXTURE_DIR = path.join(__dirname, 'fixtures', 'out');

function fixturePath(file) {
  return path.join(FIXTURE_DIR, file);
}

function loadManifest() {
  return JSON.parse(fs.readFileSync(path.join(FIXTURE_DIR, 'manifest.json'), 'utf8'));
}

// Create a single WinZip-AES ZIP via pyzipper. Returns the file path.
function makeAesZip({
  dir,
  file = 'blind.zip',
  entry = 'secreto.txt',
  content = 'contenido secreto\n',
  method = 'store',
  nbits = 256,
  password,
}) {
  const outDir = dir || fs.mkdtempSync(path.join(os.tmpdir(), 'ganzua-blind-'));
  const spec = [{ file, entry, method, nbits, password, content }];
  const res = spawnSync('python3', [path.join(__dirname, 'fixtures', 'gen_aes.py'), outDir, JSON.stringify(spec)], {
    encoding: 'utf8',
  });
  if (res.status !== 0) {
    throw new Error(`no se pudo crear el ZIP AES de prueba (¿pyzipper instalado?): ${res.stderr || res.stdout}`);
  }
  return path.join(outDir, file);
}

const CLI = path.join(__dirname, '..', 'ganzua.js');

// Run the ganzua CLI, returning { status, stdout, stderr }. `env` se mezcla con
// el entorno actual (un valor undefined elimina la variable).
function runCli(args, { env } = {}) {
  const res = spawnSync('node', [CLI, ...args], { encoding: 'utf8', env: mergeEnv(env) });
  return { status: res.status, stdout: res.stdout || '', stderr: res.stderr || '' };
}

// Igual que runCli pero sin bloquear el event loop: necesario cuando el test
// sirve en el mismo proceso algo que la CLI consulta (p. ej. una API simulada).
function runCliAsync(args, { env } = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn('node', [CLI, ...args], { env: mergeEnv(env) });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (d) => (stdout += d));
    child.stderr.on('data', (d) => (stderr += d));
    child.on('error', reject);
    child.on('close', (status) => resolve({ status, stdout, stderr }));
  });
}

function mergeEnv(env) {
  if (!env) return process.env;
  const merged = { ...process.env, ...env };
  for (const [k, v] of Object.entries(env)) if (v === undefined) delete merged[k];
  return merged;
}

module.exports = { FIXTURE_DIR, fixturePath, loadManifest, makeAesZip, runCli, runCliAsync };
