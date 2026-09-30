'use strict';

// Test helpers: mint encrypted ZIPs on demand (used by the blind-crack test),
// and load the deterministic fixture manifest.

const { spawnSync } = require('child_process');
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

// Run the ganzua CLI, returning { status, stdout, stderr }.
function runCli(args) {
  const res = spawnSync('node', [path.join(__dirname, '..', 'ganzua.js'), ...args], { encoding: 'utf8' });
  return { status: res.status, stdout: res.stdout || '', stderr: res.stderr || '' };
}

module.exports = { FIXTURE_DIR, fixturePath, loadManifest, makeAesZip, runCli };
