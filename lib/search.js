'use strict';

// Search orchestration: walk a candidate stream, test each against an entry,
// stop at the first definitive hit. Single-threaded here; worker-thread
// parallelisation is layered on top separately (it is the PBKDF2 bottleneck
// for AES that benefits, not this loop).

const { verify } = require('./verify');

// Run a search over an iterable of candidate strings.
//   entry:      parsed encrypted entry (with .crypto)
//   candidates: iterable/iterator of strings
//   onProgress: optional ({ tried, rate, last }) => void, called periodically
//   progressEvery: candidates between progress callbacks
//   limit: optional max candidates to try
// Returns { found, password, tried, elapsedMs }.
function search(entry, candidates, { onProgress, progressEvery = 500, limit } = {}) {
  const started = Date.now();
  let tried = 0;
  let lastReport = started;

  for (const candidate of candidates) {
    if (limit && tried >= limit) break;
    tried++;
    if (verify(entry, candidate)) {
      return { found: true, password: candidate, tried, elapsedMs: Date.now() - started };
    }
    if (onProgress && tried % progressEvery === 0) {
      const now = Date.now();
      const rate = (progressEvery * 1000) / Math.max(1, now - lastReport);
      lastReport = now;
      onProgress({ tried, rate, last: candidate });
    }
  }

  return { found: false, password: null, tried, elapsedMs: Date.now() - started };
}

module.exports = { search };
