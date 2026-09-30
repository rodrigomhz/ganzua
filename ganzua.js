#!/usr/bin/env node
'use strict';

// ganzua — recuperación de contraseñas de archivos ZIP (WinZip AES-256 y
// ZipCrypto), para archivos propios o cuyo análisis estés autorizado a
// realizar.
//
// Comando principal:  romper   (encuentra la contraseña sin conocerla)
// Comandos de apoyo:  analiza · material · verifica · busca

const fs = require('fs');
const os = require('os');
const path = require('path');

const { readZip, firstEncryptedEntry, ZipError } = require('./lib/zip');
const { verify } = require('./lib/verify');
const { searchAsync } = require('./lib/search');
const { searchParallel, defaultWorkers } = require('./lib/search-parallel');
const candidates = require('./lib/candidates');
const checkpoint = require('./lib/checkpoint');
const hashcat = require('./lib/hashcat');
const aesCrypto = require('./lib/crypto-aes');

// Below this many candidates the worker-pool overhead is not worth it.
const PARALLEL_THRESHOLD = 4000;

const VERSION = require('./package.json').version;

// ---------------------------------------------------------------------------
// Minimal argument parsing
// ---------------------------------------------------------------------------

const FLAGS_WITH_VALUE = new Set([
  '--wordlist',
  '--patron',
  '--mascara',
  '--limite',
  '--entrada',
  '--hilos',
  '--checkpoint',
]);

function parseArgs(argv) {
  const positionals = [];
  const opts = { json: false, agresivo: false, todas: false, secuencial: false };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--json') opts.json = true;
    else if (a === '--agresivo' || a === '--aggressive') opts.agresivo = true;
    else if (a === '--secuencial' || a === '--sequential') opts.secuencial = true;
    else if (a === '--hashcat') opts.hashcat = true;
    else if (a === '--todas' || a === '--all') opts.todas = true;
    else if (a === '--help' || a === '-h') opts.help = true;
    else if (a === '--version' || a === '-v') opts.version = true;
    else if (FLAGS_WITH_VALUE.has(a)) {
      const value = argv[++i];
      if (value === undefined) fail(`la opción ${a} necesita un valor`);
      opts[a.slice(2)] = value;
    } else if (a.startsWith('--') && a.includes('=')) {
      const [k, ...rest] = a.slice(2).split('=');
      opts[k] = rest.join('=');
    } else if (a.startsWith('-') && a !== '-') {
      fail(`opción desconocida: ${a}`);
    } else {
      positionals.push(a);
    }
  }
  return { positionals, opts };
}

function fail(msg, code = 2) {
  process.stderr.write(`ganzua: ${msg}\n`);
  process.exit(code);
}

// ---------------------------------------------------------------------------
// Output helpers
// ---------------------------------------------------------------------------

const isTTY = process.stderr.isTTY;

function out(line = '') {
  process.stdout.write(line + '\n');
}

function note(line = '') {
  process.stderr.write(line + '\n');
}

function emitJson(obj) {
  process.stdout.write(JSON.stringify(obj, null, 2) + '\n');
}

function describeEncryption(entry) {
  if (entry.encryption === 'aes') {
    const bits = aesCrypto.STRENGTH[entry.crypto.strength]?.bits ?? '?';
    const method = entry.method === 8 ? 'DEFLATE' : entry.method === 0 ? 'STORE' : `método ${entry.method}`;
    const ae = entry.aes?.version === 1 ? 'AE-1' : 'AE-2';
    return `WinZip AES-${bits} (${ae}, ${method})`;
  }
  if (entry.encryption === 'zipcrypto') {
    const method = entry.method === 8 ? 'DEFLATE' : 'STORE';
    return `ZipCrypto (PKWARE tradicional, ${method})`;
  }
  return 'sin cifrar';
}

// ---------------------------------------------------------------------------
// Target resolution
// ---------------------------------------------------------------------------

function openZip(file) {
  if (!fs.existsSync(file)) fail(`no existe el archivo: ${file}`);
  try {
    return readZip(file);
  } catch (err) {
    if (err instanceof ZipError) fail(err.message);
    throw err;
  }
}

function encryptedEntries(zip) {
  return zip.entries.filter((e) => e.encryption !== 'none');
}

function resolveEntry(zip, opts) {
  if (opts.entrada !== undefined) {
    const idx = Number(opts.entrada);
    const entry = zip.entries.find((e) => e.index === idx);
    if (!entry) fail(`no hay entrada con índice ${idx}`);
    if (entry.encryption === 'none') fail(`la entrada ${idx} ("${entry.name}") no está cifrada`);
    return entry;
  }
  const entry = firstEncryptedEntry(zip);
  if (!entry) fail('el ZIP no contiene entradas cifradas');
  return entry;
}

// ---------------------------------------------------------------------------
// Shared search runner (used by `romper` and `busca`)
// ---------------------------------------------------------------------------

function buildCandidateStream(opts) {
  const words = opts.wordlist ? candidates.loadWordlist(opts.wordlist) : undefined;
  if (opts.mascara) {
    let total;
    try {
      total = candidates.estimateMaskCount(opts.mascara);
    } catch (err) {
      fail(err.message);
    }
    return {
      stream: candidates.maskCandidates(opts.mascara),
      total,
      label: `máscara "${opts.mascara}"`,
    };
  }
  if (opts.patron) {
    return {
      stream: candidates.patternCandidates(opts.patron, { words, aggressive: opts.agresivo }),
      total: null,
      label: `patrón "${opts.patron}"`,
    };
  }
  const total = candidates.estimateCount({ words, aggressive: opts.agresivo });
  const label = opts.wordlist
    ? `wordlist ${path.basename(opts.wordlist)}${opts.agresivo ? ' + patrones (agresivo)' : ' + patrones'}`
    : opts.agresivo
      ? 'wordlist común + patrones (agresivo)'
      : 'wordlist común + patrones típicos';
  return {
    stream: candidates.romperCandidates({ words, aggressive: opts.agresivo }),
    total,
    label,
  };
}

function progressReporter(total) {
  return ({ tried, rate }) => {
    if (!isTTY) return;
    const pct = total ? ` · ${((tried / total) * 100).toFixed(0)}%` : '';
    process.stderr.write(`\r  [ ${tried} probadas · ${Math.round(rate)}/s${pct} ]        `);
  };
}

// Decide how many worker threads to use (0 => run single-threaded).
function planWorkers(entry, total, opts) {
  if (entry.encryption !== 'aes') return 0; // only AES/PBKDF2 benefits
  if (opts.secuencial) return 0;
  const requested = opts.hilos !== undefined ? Number(opts.hilos) : defaultWorkers();
  if (!Number.isFinite(requested) || requested <= 1) return 0;
  // Skip the pool for small, quick searches where its overhead dominates.
  if (total !== null && total < PARALLEL_THRESHOLD) return 0;
  return requested;
}

async function runSearch(zip, entry, opts) {
  const { stream, total, label } = buildCandidateStream(opts);
  const limit = opts.limite ? Number(opts.limite) : undefined;
  const workers = planWorkers(entry, total, opts);

  // Checkpoint / resume.
  const cpFile = opts.checkpoint;
  const firma = cpFile ? checkpoint.signature(zip.path, entry.index, opts) : null;
  let startAt = 0;
  if (cpFile) {
    const cp = checkpoint.load(cpFile);
    if (cp && cp.firma === firma && cp.position > 0) {
      startAt = cp.position;
      if (!opts.json) note(`  reanudando desde la candidata ${startAt} (checkpoint)`);
    }
  }
  const onCheckpoint = cpFile
    ? (position) => checkpoint.save(cpFile, { firma, archivo: zip.path, entrada: entry.index, position, total })
    : undefined;

  if (!opts.json) {
    note(`ganzua · rompiendo ${path.basename(zip.path)}`);
    note(`  cifrado: ${describeEncryption(entry)} — entrada "${entry.name}"`);
    const paralelo = workers > 0 ? ` · ${workers} hilos` : '';
    note(`  probando ${label}${total ? ` (~${total} candidatas)` : ''}${paralelo}…`);
  }

  // Abort on SIGINT (Ctrl+C): stop cleanly, summarise, save checkpoint.
  const ac = new AbortController();
  let interrupted = false;
  const onSigint = () => {
    if (interrupted) process.exit(130); // segundo Ctrl+C: salida inmediata
    interrupted = true;
    ac.abort();
  };
  process.on('SIGINT', onSigint);

  const onProgress = opts.json ? undefined : progressReporter(total);
  const common = { onProgress, limit, startAt, signal: ac.signal, onCheckpoint };
  let result;
  try {
    result =
      workers > 0
        ? await searchParallel(entry, stream, { workers, ...common })
        : await searchAsync(entry, stream, common);
  } finally {
    process.off('SIGINT', onSigint);
  }

  if (isTTY && !opts.json) process.stderr.write('\r' + ' '.repeat(48) + '\r');

  // Interrupted: persist progress and report a summary.
  if (result.stopped) {
    if (cpFile) {
      checkpoint.save(cpFile, { firma, archivo: zip.path, entrada: entry.index, position: result.position, total });
    }
    const secs = (result.elapsedMs / 1000).toFixed(1);
    if (opts.json) {
      emitJson({
        archivo: zip.path,
        entrada: { indice: entry.index, nombre: entry.name },
        encontrada: false,
        interrumpida: true,
        posicion: result.position,
        candidatas: result.tried,
        ms: result.elapsedMs,
        checkpoint: cpFile || null,
      });
    } else {
      note('');
      note(`  ⏸ interrumpida: ${result.tried} candidatas probadas (posición ${result.position}) en ${secs} s`);
      if (cpFile) note(`  checkpoint guardado en ${cpFile} — reanuda con: --checkpoint ${cpFile}`);
      else note('  (usa --checkpoint <fichero> para poder reanudar)');
    }
    return 130;
  }

  // Búsqueda terminada (encontrada o agotada): el checkpoint ya no sirve.
  if (cpFile) checkpoint.remove(cpFile);

  if (opts.json) {
    const abre = result.found
      ? encryptedEntries(zip)
          .filter((e) => verify(e, result.password))
          .map((e) => ({ indice: e.index, nombre: e.name }))
      : [];
    emitJson({
      archivo: zip.path,
      entrada: { indice: entry.index, nombre: entry.name },
      cifrado: describeEncryption(entry),
      encontrada: result.found,
      contrasena: result.password,
      candidatas: result.tried,
      ms: result.elapsedMs,
      abre,
    });
    return result.found ? 0 : 1;
  }

  const secs = (result.elapsedMs / 1000).toFixed(1);
  if (result.found) {
    // La contraseña suele abrir todas las entradas del ZIP: comprobémoslo.
    const opened = encryptedEntries(zip)
      .filter((e) => verify(e, result.password))
      .map((e) => ({ indice: e.index, nombre: e.name }));
    out('');
    out(`  ✔ CONTRASEÑA ENCONTRADA: «${result.password}»`);
    out(`    (${result.tried} candidatas en ${secs} s)`);
    if (opened.length > 1) {
      out(`    abre ${opened.length} entradas: ${opened.map((o) => o.nombre).join(', ')}`);
    }
    return 0;
  }

  note('');
  note(`  ✗ no encontrada (${result.tried} candidatas en ${secs} s)`);
  note('  Prueba a continuación:');
  note(`    • wordlist más grande:  ganzua romper ${path.basename(zip.path)} --wordlist grande.txt`);
  if (!opts.agresivo) {
    note(`    • modo agresivo:        ganzua romper ${path.basename(zip.path)} --agresivo`);
  }
  note(`    • patrón a medida:      ganzua romper ${path.basename(zip.path)} --patron "Palabra_%s_%d"`);
  if (entry.encryption === 'aes') {
    note(`    • GPU / hashcat:        ganzua material ${path.basename(zip.path)} > hash.txt   (modo 13600)`);
  }
  return 1;
}

// ---------------------------------------------------------------------------
// Commands
// ---------------------------------------------------------------------------

// Materializa el flujo de candidatas (no-máscara) a un fichero de diccionario
// para pasárselo a hashcat en modo -a 0. Se limita para no crear ficheros
// gigantescos con --agresivo o wordlists enormes.
function materializeWordlist(opts, cap = 2_000_000) {
  const { stream } = buildCandidateStream(opts);
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ganzua-wl-'));
  const file = path.join(dir, 'words.txt');
  const fd = fs.openSync(file, 'w');
  let count = 0;
  let truncated = false;
  let buf = '';
  for (const c of stream) {
    buf += c + '\n';
    count++;
    if (buf.length >= 1 << 16) {
      fs.writeSync(fd, buf);
      buf = '';
    }
    if (count >= cap) {
      truncated = true;
      break;
    }
  }
  if (buf) fs.writeSync(fd, buf);
  fs.closeSync(fd);
  return { file, dir, count, truncated };
}

// Delega en hashcat (modo 13600) para una entrada AES.
async function runHashcat(zip, entry, opts) {
  const hash = buildZip2Hash(entry);
  let attack;
  let source;
  let info;
  let cleanup = () => {};
  if (opts.mascara) {
    attack = 'mask';
    source = opts.mascara; // la sintaxis de máscara de ganzua es la de hashcat
    info = `máscara "${opts.mascara}"`;
  } else {
    const mat = materializeWordlist(opts);
    attack = 'wordlist';
    source = mat.file;
    cleanup = () => fs.rmSync(mat.dir, { recursive: true, force: true });
    info = `diccionario de ${mat.count} candidatas${mat.truncated ? ' (truncado)' : ''}`;
  }

  if (!opts.json) {
    note(`ganzua · rompiendo ${path.basename(zip.path)} con hashcat -m 13600`);
    note(`  cifrado: ${describeEncryption(entry)} — entrada "${entry.name}"`);
    note(`  ${info}…`);
  }

  const started = Date.now();
  let result;
  try {
    result = hashcat.run({ hash, attack, source });
  } finally {
    cleanup();
  }
  const elapsedMs = Date.now() - started;
  const secs = (elapsedMs / 1000).toFixed(1);

  if (opts.json) {
    const abre = result.found
      ? encryptedEntries(zip)
          .filter((e) => verify(e, result.password))
          .map((e) => ({ indice: e.index, nombre: e.name }))
      : [];
    emitJson({
      archivo: zip.path,
      entrada: { indice: entry.index, nombre: entry.name },
      motor: 'hashcat',
      cifrado: describeEncryption(entry),
      encontrada: result.found,
      contrasena: result.password,
      ms: elapsedMs,
      abre,
    });
    return result.found ? 0 : 1;
  }

  if (result.found) {
    out('');
    out(`  ✔ CONTRASEÑA ENCONTRADA (hashcat): «${result.password}»`);
    out(`    (${secs} s)`);
    return 0;
  }
  note('');
  note(`  ✗ hashcat no encontró la contraseña (${secs} s)`);
  return 1;
}

// Elige motor: hashcat (si se pide y está disponible para AES) o el propio.
async function crack(zip, entry, opts) {
  if (opts.hashcat) {
    if (entry.encryption !== 'aes') {
      note('  hashcat (modo 13600) solo cubre AES; usando el motor propio');
    } else if (!hashcat.isAvailable()) {
      note('  hashcat no está en el PATH; usando el motor propio');
    } else {
      return runHashcat(zip, entry, opts);
    }
  }
  return runSearch(zip, entry, opts);
}

async function cmdRomper(positionals, opts) {
  const [file] = positionals;
  if (!file) fail('uso: ganzua romper <archivo.zip> [--wordlist f] [--patron p] [--agresivo] [--json]');
  const zip = openZip(file);
  const entry = resolveEntry(zip, opts);
  return crack(zip, entry, opts);
}

// `busca` is the lower-level form of `romper`: same engine, but it requires you
// to name a source (a wordlist file or a --patron) rather than defaulting to
// the bundled list.
async function cmdBusca(positionals, opts) {
  const [file, maybeWordlist] = positionals;
  if (!file) fail('uso: ganzua busca <archivo.zip> [wordlist.txt | --patron "..."] [--agresivo] [--json]');
  if (maybeWordlist && !opts.wordlist && !opts.patron && !opts.mascara) opts.wordlist = maybeWordlist;
  if (!opts.wordlist && !opts.patron && !opts.mascara) {
    fail('busca necesita una wordlist, --patron o --mascara (para valores por defecto usa: ganzua romper)');
  }
  const zip = openZip(file);
  const entry = resolveEntry(zip, opts);
  return crack(zip, entry, opts);
}

function cmdAnaliza(positionals, opts) {
  const [file] = positionals;
  if (!file) fail('uso: ganzua analiza <archivo.zip> [--json]');
  const zip = openZip(file);

  const report = zip.entries.map((e) => {
    const base = {
      indice: e.index,
      nombre: e.name,
      cifrado: e.encryption,
      metodo: e.method === 8 ? 'DEFLATE' : e.method === 0 ? 'STORE' : `método ${e.method}`,
      tamano_comprimido: e.compressedSize,
      tamano_original: e.uncompressedSize,
    };
    if (e.encryption === 'aes') {
      base.aes = {
        fuerza_bits: aesCrypto.STRENGTH[e.crypto.strength]?.bits,
        version: e.aes?.version === 1 ? 'AE-1' : 'AE-2',
        salt: e.crypto.salt.toString('hex'),
        verificador: e.crypto.verify.toString('hex'),
        auth: e.crypto.auth.toString('hex'),
      };
    } else if (e.encryption === 'zipcrypto') {
      base.zipcrypto = {
        check_byte_desde: e.flags & 0x08 ? 'mod-time' : 'crc32',
        cabecera: e.crypto.header.toString('hex'),
      };
    }
    return base;
  });

  if (opts.json) {
    emitJson({ archivo: zip.path, zip64: zip.zip64, entradas: report });
    return 0;
  }

  out(`ganzua · análisis de ${path.basename(zip.path)}`);
  if (zip.zip64) out('  (ZIP64)');
  for (const e of report) {
    out('');
    out(`  [${e.indice}] ${e.nombre}`);
    out(`      cifrado: ${describeEncryption(zip.entries[e.indice])}`);
    out(`      tamaño:  ${e.tamano_original} B (comprimido ${e.tamano_comprimido} B)`);
    if (e.aes) {
      out(`      salt:    ${e.aes.salt}`);
      out(`      verif.:  ${e.aes.verificador}   auth: ${e.aes.auth}`);
    } else if (e.zipcrypto) {
      out(`      check byte desde: ${e.zipcrypto.check_byte_desde}`);
    }
  }
  return 0;
}

// hashcat mode 13600 / John zip2john "$zip2$" hash for an AES entry.
function buildZip2Hash(entry) {
  const c = entry.crypto;
  const dataHex = c.ciphertext.toString('hex');
  const lenHex = c.ciphertext.length.toString(16);
  return [
    '$zip2$',
    '0', // type
    String(c.strength), // 1/2/3 => 128/192/256
    '0', // magic
    c.salt.toString('hex'),
    c.verify.toString('hex'),
    lenHex,
    dataHex,
    c.auth.toString('hex'),
    '$/zip2$',
  ].join('*');
}

function cmdMaterial(positionals, opts) {
  const [file] = positionals;
  if (!file) fail('uso: ganzua material <archivo.zip> [--entrada N] [--json]');
  const zip = openZip(file);
  if (opts.todas) return cmdMaterialTodas(zip, opts);
  const entry = resolveEntry(zip, opts);
  if (entry.encryption !== 'aes') {
    fail(`material genera hashes AES (modo 13600); la entrada "${entry.name}" es ${entry.encryption}`);
  }
  const hash = buildZip2Hash(entry);
  if (opts.json) {
    emitJson({
      archivo: zip.path,
      entrada: { indice: entry.index, nombre: entry.name },
      modo_hashcat: 13600,
      fuerza_bits: aesCrypto.STRENGTH[entry.crypto.strength]?.bits,
      salt: entry.crypto.salt.toString('hex'),
      verificador: entry.crypto.verify.toString('hex'),
      auth: entry.crypto.auth.toString('hex'),
      hash,
    });
    return 0;
  }
  out(hash);
  return 0;
}

function cmdMaterialTodas(zip, opts) {
  const aesEntries = encryptedEntries(zip).filter((e) => e.encryption === 'aes');
  if (aesEntries.length === 0) fail('el ZIP no contiene entradas AES');
  if (opts.json) {
    emitJson({
      archivo: zip.path,
      modo_hashcat: 13600,
      hashes: aesEntries.map((e) => ({ indice: e.index, nombre: e.name, hash: buildZip2Hash(e) })),
    });
    return 0;
  }
  for (const e of aesEntries) out(buildZip2Hash(e));
  return 0;
}

function cmdVerifica(positionals, opts) {
  const [file, password] = positionals;
  if (!file || password === undefined) fail('uso: ganzua verifica <archivo.zip> <candidata> [--json]');
  const zip = openZip(file);

  if (opts.todas) {
    const enc = encryptedEntries(zip);
    if (enc.length === 0) fail('el ZIP no contiene entradas cifradas');
    const resultados = enc.map((e) => ({ indice: e.index, nombre: e.name, valida: verify(e, password) }));
    const todas = resultados.every((r) => r.valida);
    if (opts.json) {
      emitJson({ archivo: zip.path, candidata: password, valida_todas: todas, entradas: resultados });
      return todas ? 0 : 1;
    }
    for (const r of resultados) out(`${r.valida ? '✔' : '✗'} [${r.indice}] ${r.nombre}`);
    return todas ? 0 : 1;
  }

  const entry = resolveEntry(zip, opts);
  const ok = verify(entry, password);
  if (opts.json) {
    emitJson({
      archivo: zip.path,
      entrada: { indice: entry.index, nombre: entry.name },
      candidata: password,
      valida: ok,
    });
    return ok ? 0 : 1;
  }
  if (ok) out(`✔ contraseña válida: «${password}»`);
  else out(`✗ contraseña incorrecta: «${password}»`);
  return ok ? 0 : 1;
}

// ---------------------------------------------------------------------------
// Help / version
// ---------------------------------------------------------------------------

function printHelp() {
  out(`ganzua ${VERSION} — recupera la contraseña de archivos ZIP cifrados
(WinZip AES-256 y ZipCrypto). Para archivos propios o cuyo análisis estés
autorizado a realizar.

USO
  ganzua <comando> <archivo.zip> [opciones]

COMANDO PRINCIPAL
  romper <archivo.zip>       Encuentra la contraseña sin conocerla: detecta el
                             cifrado y prueba una wordlist común incluida más
                             patrones típicos (palabra+año, mayúscula+número,
                             año+sufijo). Si no la encuentra, indica qué probar.
      --wordlist <fichero>   Usa tu propia wordlist en vez de la incluida.
      --patron "<plantilla>" Genera candidatas desde una plantilla (ver abajo).
      --mascara "<máscara>"  Ataque por máscara estilo hashcat (ver abajo).
      --agresivo             Amplía años y sufijos automáticamente.
      --hilos <N>            Nº de hilos (AES). Por defecto: nº de CPUs.
      --secuencial           Fuerza búsqueda en un solo hilo.
      --hashcat              Usa hashcat (modo 13600) si está en el PATH; si no,
                             recurre al motor propio.
      --checkpoint <fichero> Guarda el progreso y reanuda desde él (búsquedas
                             largas). Ctrl+C guarda y sale con un resumen.
      --json                 Salida JSON.

COMANDOS DE APOYO
  analiza  <archivo.zip>     Detecta el cifrado y muestra salt/verificador.
  material <archivo.zip>     Emite el hash "$zip2$" para hashcat -m 13600 / John.
  verifica <archivo.zip> <c> Prueba una única candidata.
  busca    <archivo.zip> ... Búsqueda de bajo nivel (requiere wordlist o --patron).

OPCIONES COMUNES
  --entrada <N>              Índice de entrada a atacar (por defecto, la primera
                             cifrada). Usa "analiza" para ver los índices.
  --todas                    Opera sobre todas las entradas cifradas
                             (verifica/material). En romper indica qué entradas
                             abre la contraseña encontrada.
  --json                     Salida en JSON.
  -h, --help                 Esta ayuda.       -v, --version   Versión.

PLANTILLAS DE --patron
  %s palabra de la wordlist   %c palabra capitalizada   %y año
  %n dígito 0-9               %D número 00-99
  Ejemplo:  ganzua romper archivo.zip --patron "Palabra_%s_%y"

MÁSCARAS DE --mascara
  ?l a-z   ?u A-Z   ?d 0-9   ?s símbolos   ?a todo   ?? literal "?"
  El resto de caracteres son literales.
  Ejemplo:  ganzua romper archivo.zip --mascara "Casa?d?d?d?d"

EJEMPLOS
  ganzua romper   archivo.zip
  ganzua romper   archivo.zip --agresivo
  ganzua romper   archivo.zip --wordlist rockyou.txt
  ganzua analiza  archivo.zip
  ganzua material archivo.zip > hash.txt
  ganzua verifica archivo.zip "Secreto_2024"

Uso autorizado únicamente. No utilices ganzua contra archivos que no te
pertenezcan o para los que no tengas permiso explícito.`);
}

// ---------------------------------------------------------------------------
// Dispatch
// ---------------------------------------------------------------------------

const COMMANDS = {
  romper: cmdRomper,
  busca: cmdBusca,
  analiza: cmdAnaliza,
  material: cmdMaterial,
  verifica: cmdVerifica,
};

async function main(argv) {
  const { positionals, opts } = parseArgs(argv);
  const command = positionals.shift();

  if (opts.version || command === 'version') {
    out(`ganzua ${VERSION}`);
    return 0;
  }
  if (!command || command === 'help' || opts.help) {
    printHelp();
    return 0;
  }

  const handler = COMMANDS[command];
  if (!handler) {
    fail(`comando desconocido: ${command}\nEjecuta "ganzua --help" para ver los comandos.`);
  }

  try {
    return (await handler(positionals, opts)) || 0;
  } catch (err) {
    if (err instanceof ZipError) fail(err.message);
    throw err;
  }
}

if (require.main === module) {
  main(process.argv.slice(2)).then(
    (code) => process.exit(code),
    (err) => {
      process.stderr.write(`ganzua: ${err && err.stack ? err.stack : err}\n`);
      process.exit(1);
    },
  );
}

module.exports = { main, parseArgs, buildZip2Hash };
