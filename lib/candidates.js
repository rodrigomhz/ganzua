'use strict';

// Candidate password generation for `romper` / `busca`.
//
// Given a base wordlist, produce a lazy stream of candidates applying the
// patterns people actually use: the word itself, capitalised, word+year,
// word+suffix, and year+suffix. `--agresivo` widens the year range and the
// suffix set. Everything is generated lazily (generators, not arrays) so
// aggressive runs of millions of candidates stay memory-light.

const fs = require('fs');
const path = require('path');

const BUNDLED_WORDLIST = path.join(__dirname, '..', 'data', 'wordlist-comunes.txt');

// Load a wordlist file: one candidate per line, blank lines skipped, CR
// trimmed, duplicates removed while preserving order. Lines are treated
// literally (no comment syntax) so any password is expressible.
function loadWordlist(file) {
  const text = fs.readFileSync(file, 'utf8');
  const seen = new Set();
  const words = [];
  for (const raw of text.split('\n')) {
    const w = raw.replace(/\r$/, '');
    if (w.length === 0) continue;
    if (seen.has(w)) continue;
    seen.add(w);
    words.push(w);
  }
  return words;
}

function loadBundledWordlist() {
  return loadWordlist(BUNDLED_WORDLIST);
}

function capitalize(word) {
  if (word.length === 0) return word;
  return word[0].toUpperCase() + word.slice(1);
}

function range(from, to) {
  const out = [];
  const step = from <= to ? 1 : -1;
  for (let n = from; step > 0 ? n <= to : n >= to; n += step) out.push(n);
  return out;
}

// Build the year/suffix parameter sets for a mode.
function buildOptions({ aggressive = false, year = new Date().getFullYear() } = {}) {
  if (aggressive) {
    const suffixes = new Set([
      '1',
      '12',
      '123',
      '1234',
      '12345',
      '123456',
      '!',
      '!!',
      '?',
      '.',
      '@',
      '#',
      '$',
      '*',
      '_',
      '-',
      '01',
      '00',
      '000',
      '007',
      '69',
      '420',
      '666',
      '777',
      '911',
      '2',
      '3',
      '21',
      '99',
      '111',
      '321',
      '123!',
      '!123',
      String(year),
    ]);
    for (let n = 0; n <= 99; n++) suffixes.add(String(n).padStart(n < 10 ? 1 : 2, '0'));
    for (let n = 0; n <= 9; n++) suffixes.add(`0${n}`);
    return {
      years: range(year + 1, 1970).map(String),
      suffixes: [...suffixes],
      yearSuffixes: ['', '!', '.', '?'],
    };
  }
  return {
    years: range(year + 1, year - 20).map(String),
    suffixes: ['1', '12', '123', '1234', '!', '.', '01', '007', '00'],
    yearSuffixes: ['', '!'],
  };
}

// The core mutation stream. Ordered so that the most likely forms come first.
function* mutate(words, opts) {
  const { years, suffixes, yearSuffixes } = opts;

  // 1. raw words
  for (const w of words) yield w;

  // 2. capitalised (initial uppercase), only when it changes the word
  for (const w of words) {
    const c = capitalize(w);
    if (c !== w) yield c;
  }

  // 3. word + suffix
  for (const w of words) for (const s of suffixes) yield w + s;

  // 4. Capitalised + suffix (mayúscula inicial + número)
  for (const w of words) {
    const c = capitalize(w);
    if (c === w) continue;
    for (const s of suffixes) yield c + s;
  }

  // 5. word + year (palabra+año)
  for (const w of words) for (const y of years) yield w + y;

  // 6. Capitalised + year
  for (const w of words) {
    const c = capitalize(w);
    if (c === w) continue;
    for (const y of years) yield c + y;
  }

  // 7. year + suffix (año+sufijo)
  for (const y of years) for (const s of yearSuffixes) yield y + s;
}

const LEET = { a: '4', e: '3', i: '1', o: '0', s: '5', t: '7', b: '8', g: '9' };

function leet(word) {
  let out = '';
  for (const ch of word) out += LEET[ch.toLowerCase()] || ch;
  return out;
}

const RULE_SEPARATORS = ['_', '-', '.'];

// Extra mutations enabled with `--reglas`: leet, MAYÚSCULAS, reverso y
// separadores (palabra_año, palabra-sufijo). Se emiten tras las básicas.
function* ruleMutations(words, opts) {
  const { years, suffixes } = opts;

  for (const w of words) {
    const up = w.toUpperCase();
    if (up !== w && up !== capitalize(w)) yield up; // MAYÚSCULAS
    const rev = [...w].reverse().join('');
    if (rev !== w) yield rev; // reverso
    const l = leet(w);
    if (l !== w) yield l; // leet
  }

  // palabra + separador + año  y  Mayúscula + separador + año
  for (const w of words) {
    const c = capitalize(w);
    for (const sep of RULE_SEPARATORS) {
      for (const y of years) {
        yield w + sep + y;
        if (c !== w) yield c + sep + y;
      }
    }
  }

  // palabra + separador + sufijo
  for (const w of words) {
    for (const sep of RULE_SEPARATORS) {
      for (const s of suffixes) yield w + sep + s;
    }
  }
}

// Public: a candidate stream from a wordlist + mode.
function romperCandidates({ words, aggressive = false, year, rules = false } = {}) {
  const list = words || loadBundledWordlist();
  const opts = buildOptions({ aggressive, year });
  if (!rules) return mutate(list, opts);
  return (function* () {
    yield* mutate(list, opts);
    yield* ruleMutations(list, opts);
  })();
}

// Estimate the number of candidates a mode/wordlist will produce (for progress
// reporting) without materialising the stream.
function estimateCount({ words, aggressive = false, year, rules = false } = {}) {
  const list = words || loadBundledWordlist();
  const opts = buildOptions({ aggressive, year });
  let capitalizable = 0;
  for (const w of list) if (capitalize(w) !== w) capitalizable++;
  const n = list.length;
  const s = opts.suffixes.length;
  const y = opts.years.length;
  let total =
    n + // raw
    capitalizable + // capitalised
    n * s + // word+suffix
    capitalizable * s + // Cap+suffix
    n * y + // word+year
    capitalizable * y + // Cap+year
    y * opts.yearSuffixes.length; // year+suffix
  if (rules) {
    const seps = RULE_SEPARATORS.length;
    total +=
      3 * n + // MAYÚSCULAS + reverso + leet (aprox.)
      n * seps * y + // palabra+sep+año
      capitalizable * seps * y + // Cap+sep+año
      n * seps * s; // palabra+sep+sufijo
  }
  return total;
}

// Expand a `--patron` template into a candidate stream. Placeholders:
//   %s  wordlist word          %c  wordlist word capitalised
//   %y  year (mode range)      %n  digit 0-9        %D  number 00-99
// Literal text is kept as-is. Multiple placeholders expand as a cartesian
// product, left-most varying slowest.
function* patternCandidates(template, { words, aggressive = false, year } = {}) {
  const list = words || loadBundledWordlist();
  const opts = buildOptions({ aggressive, year });
  const digits = range(0, 9).map(String);
  const twoDigits = range(0, 99).map((n) => String(n).padStart(2, '0'));

  const sources = {
    '%s': list,
    '%c': list.map(capitalize),
    '%y': opts.years,
    '%n': digits,
    '%D': twoDigits,
  };

  // Split the template into literal chunks and placeholder tokens.
  const tokens = [];
  const re = /%[scynD]/g;
  let last = 0;
  let m;
  while ((m = re.exec(template)) !== null) {
    if (m.index > last) tokens.push({ lit: template.slice(last, m.index) });
    tokens.push({ ph: m[0] });
    last = m.index + m[0].length;
  }
  if (last < template.length) tokens.push({ lit: template.slice(last) });

  const placeholders = tokens.filter((t) => t.ph);
  if (placeholders.length === 0) {
    yield template;
    return;
  }

  const idx = new Array(placeholders.length).fill(0);
  for (;;) {
    let out = '';
    let p = 0;
    for (const t of tokens) {
      if (t.lit) out += t.lit;
      else out += sources[t.ph][idx[p++]];
    }
    yield out;

    // Odometer increment, right-most placeholder fastest.
    let k = placeholders.length - 1;
    for (; k >= 0; k--) {
      const src = sources[placeholders[k].ph];
      if (++idx[k] < src.length) break;
      idx[k] = 0;
    }
    if (k < 0) break;
  }
}

// ---------------------------------------------------------------------------
// Ataque por máscara estilo hashcat: ?l ?u ?d ?s ?a y literales.
// ---------------------------------------------------------------------------

const MASK_SETS = {
  l: 'abcdefghijklmnopqrstuvwxyz',
  u: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
  d: '0123456789',
  s: ' !"#$%&\'()*+,-./:;<=>?@[\\]^_`{|}~',
};
MASK_SETS.a = MASK_SETS.l + MASK_SETS.u + MASK_SETS.d + MASK_SETS.s;

// Convierte una máscara en un array de conjuntos (uno por posición).
function parseMask(mask) {
  const positions = [];
  for (let i = 0; i < mask.length; i++) {
    const ch = mask[i];
    if (ch === '?') {
      const token = mask[i + 1];
      if (token === undefined) throw new Error(`máscara incompleta: "?" al final`);
      i++;
      if (token === '?') positions.push('?');
      else if (MASK_SETS[token]) positions.push(MASK_SETS[token]);
      else throw new Error(`token de máscara desconocido: ?${token} (usa ?l ?u ?d ?s ?a ??)`);
    } else {
      positions.push(ch); // literal
    }
  }
  if (positions.length === 0) throw new Error('máscara vacía');
  return positions;
}

// Nº de candidatas de una máscara, o null si excede el entero seguro.
function estimateMaskCount(mask) {
  const positions = parseMask(mask);
  let n = 1;
  for (const p of positions) {
    n *= p.length;
    if (n > Number.MAX_SAFE_INTEGER) return null;
  }
  return n;
}

// Flujo perezoso de todas las combinaciones de la máscara (odómetro).
function* maskCandidates(mask) {
  const positions = parseMask(mask);
  const idx = new Array(positions.length).fill(0);
  const len = positions.length;
  for (;;) {
    let out = '';
    for (let p = 0; p < len; p++) out += positions[p][idx[p]];
    yield out;
    let k = len - 1;
    for (; k >= 0; k--) {
      if (++idx[k] < positions[k].length) break;
      idx[k] = 0;
    }
    if (k < 0) break;
  }
}

module.exports = {
  BUNDLED_WORDLIST,
  MASK_SETS,
  loadWordlist,
  loadBundledWordlist,
  capitalize,
  leet,
  buildOptions,
  mutate,
  ruleMutations,
  romperCandidates,
  estimateCount,
  patternCandidates,
  parseMask,
  estimateMaskCount,
  maskCandidates,
};
