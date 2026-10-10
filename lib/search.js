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
function search(entry, candidates, { onProgress, progressEvery = 500, limit, encoding = 'utf8' } = {}) {
  const started = Date.now();
  let tried = 0;
  let lastReport = started;

  for (const candidate of candidates) {
    if (limit && tried >= limit) break;
    tried++;
    if (verify(entry, candidate, { encoding })) {
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

// Interruptible, resumable variant. A synchronous tight loop never lets a
// SIGINT handler run, so this yields to the event loop every `chunk`
// candidates and checks the abort signal there. Supports resuming (startAt)
// and periodic checkpoints.
//   startAt:        candidates to skip from the start of the stream (resume)
//   signal:         AbortSignal; when aborted the search stops cleanly
//   onCheckpoint:   (position) => void, called ~every checkpointEvery
// Returns { found, password, tried, position, stopped, exhausted, elapsedMs }.
async function searchAsync(
  entry,
  candidates,
  {
    onProgress,
    progressEvery = 500,
    limit,
    startAt = 0,
    signal,
    onCheckpoint,
    checkpointEvery = 5000,
    chunk = 256,
    encoding = 'utf8',
  } = {},
) {
  const iter = candidates[Symbol.iterator] ? candidates[Symbol.iterator]() : candidates;
  const started = Date.now();
  let position = 0;

  // Skip already-tried candidates when resuming.
  while (position < startAt) {
    const r = iter.next();
    if (r.done) break;
    position++;
  }

  let tried = 0;
  let lastReport = started;
  let lastCheckpoint = position;

  for (;;) {
    if (signal && signal.aborted) {
      return { found: false, password: null, tried, position, stopped: true, elapsedMs: Date.now() - started };
    }
    for (let i = 0; i < chunk; i++) {
      if (limit && tried >= limit) {
        return { found: false, password: null, tried, position, exhausted: false, elapsedMs: Date.now() - started };
      }
      const r = iter.next();
      if (r.done) {
        return { found: false, password: null, tried, position, exhausted: true, elapsedMs: Date.now() - started };
      }
      position++;
      tried++;
      if (verify(entry, r.value, { encoding })) {
        return { found: true, password: r.value, tried, position, elapsedMs: Date.now() - started };
      }
      if (onProgress && tried % progressEvery === 0) {
        const now = Date.now();
        const rate = (progressEvery * 1000) / Math.max(1, now - lastReport);
        lastReport = now;
        onProgress({ tried, rate, last: r.value });
      }
    }
    if (onCheckpoint && position - lastCheckpoint >= checkpointEvery) {
      lastCheckpoint = position;
      onCheckpoint(position);
    }
    await new Promise((r) => setImmediate(r)); // ceder al event loop (SIGINT)
  }
}

module.exports = { search, searchAsync };
