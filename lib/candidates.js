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
      '1', '12', '123', '1234', '12345', '123456',
      '!', '!!', '?', '.', '@', '#', '$', '*', '_', '-',
      '01', '00', '000', '007', '69', '420', '666', '777', '911',
      '2', '3', '21', '99', '111', '321', '123!', '!123', String(year),
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

// Public: a candidate stream from a wordlist + mode.
function romperCandidates({ words, aggressive = false, year } = {}) {
  const list = words || loadBundledWordlist();
  const opts = buildOptions({ aggressive, year });
  return mutate(list, opts);
}

// Estimate the number of candidates a mode/wordlist will produce (for progress
// reporting) without materialising the stream.
function estimateCount({ words, aggressive = false, year } = {}) {
  const list = words || loadBundledWordlist();
  const opts = buildOptions({ aggressive, year });
  let capitalizable = 0;
  for (const w of list) if (capitalize(w) !== w) capitalizable++;
  const n = list.length;
  const s = opts.suffixes.length;
  const y = opts.years.length;
  return (
    n + // raw
    capitalizable + // capitalised
    n * s + // word+suffix
    capitalizable * s + // Cap+suffix
    n * y + // word+year
    capitalizable * y + // Cap+year
    y * opts.yearSuffixes.length // year+suffix
  );
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

module.exports = {
  BUNDLED_WORDLIST,
  loadWordlist,
  loadBundledWordlist,
  capitalize,
  buildOptions,
  mutate,
  romperCandidates,
  estimateCount,
  patternCandidates,
};
