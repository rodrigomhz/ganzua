'use strict';

// Parallel search for AES entries using a worker pool. The main thread pulls
// candidates from the stream, hands out fixed-size batches, and stops every
// worker the moment one reports a hit. Only AES benefits meaningfully (PBKDF2
// is CPU-bound); ZipCrypto stays on the single-threaded path.
//
// Supports resuming (startAt) and abort (signal). Because workers finish
// batches out of order, the resumable "committed" position is the length of
// the contiguous prefix of completed batches — never a gap.

const os = require('os');
const path = require('path');
const { Worker } = require('worker_threads');

function defaultWorkers() {
  return Math.max(1, (os.cpus() || []).length || 1);
}

// Returns a Promise<{ found, password, tried, position, stopped, exhausted, elapsedMs }>.
function searchParallel(entry, candidates, { workers, batchSize = 800, onProgress, progressEvery = 2000, limit, startAt = 0, signal, onCheckpoint, checkpointEvery = 5000 } = {}) {
  return new Promise((resolve, reject) => {
    const n = Math.max(1, workers || defaultWorkers());
    const material = {
      strength: entry.crypto.strength,
      salt: entry.crypto.salt,
      verify: entry.crypto.verify,
      ciphertext: entry.crypto.ciphertext,
      auth: entry.crypto.auth,
    };

    const iter = candidates[Symbol.iterator] ? candidates[Symbol.iterator]() : candidates;
    const started = Date.now();
    const pool = [];

    // Skip already-tried candidates when resuming.
    let fed = 0;
    while (fed < startAt) {
      const r = iter.next();
      if (r.done) break;
      fed++;
    }

    let committed = fed; // contiguous verified prefix (safe resume point)
    let tried = 0;
    let busy = 0;
    let aborting = false;
    let settled = false;
    let lastReport = started;
    let lastReportTried = 0;
    let lastCheckpoint = committed;
    const completed = new Map(); // start -> len, for batches not yet folded into `committed`

    function advanceCommitted() {
      while (completed.has(committed)) {
        const len = completed.get(committed);
        completed.delete(committed);
        committed += len;
      }
      if (onCheckpoint && committed - lastCheckpoint >= checkpointEvery) {
        lastCheckpoint = committed;
        onCheckpoint(committed);
      }
    }

    function nextBatch() {
      const start = fed;
      const batch = [];
      while (batch.length < batchSize) {
        if (limit && fed - startAt >= limit) break;
        const r = iter.next();
        if (r.done) break;
        batch.push(r.value);
        fed++;
      }
      return batch.length ? { batch, start, len: batch.length } : null;
    }

    function finish(result) {
      if (settled) return;
      settled = true;
      for (const w of pool) w.terminate();
      resolve(result);
    }

    function assign(worker) {
      if (settled) return;
      if (aborting) {
        busy--;
        if (busy === 0) finish({ found: false, password: null, tried, position: committed, stopped: true, elapsedMs: Date.now() - started });
        return;
      }
      const next = nextBatch();
      if (!next) {
        busy--;
        if (busy === 0) finish({ found: false, password: null, tried, position: committed, exhausted: true, elapsedMs: Date.now() - started });
        return;
      }
      worker.pending = { start: next.start, len: next.len };
      worker.postMessage({ batch: next.batch });
    }

    if (signal) {
      if (signal.aborted) aborting = true;
      else signal.addEventListener('abort', () => { aborting = true; }, { once: true });
    }

    // Create every worker first, then start assigning. If we assigned inside
    // the creation loop, an immediate exhaustion (e.g. a resume that skips the
    // whole stream) could drive `busy` to 0 and terminate the pool before the
    // remaining workers were even created — leaking them.
    for (let i = 0; i < n; i++) {
      let worker;
      try {
        worker = new Worker(path.join(__dirname, 'worker-aes.js'), { workerData: { material } });
      } catch (err) {
        for (const w of pool) w.terminate();
        return reject(err);
      }
      pool.push(worker);
      worker.on('message', (msg) => {
        if (settled) return;
        const pending = worker.pending;
        if (msg.found) {
          finish({ found: true, password: msg.password, tried: committed + (msg.triedInBatch || 0), position: committed, elapsedMs: Date.now() - started });
          return;
        }
        tried += msg.tried;
        if (pending) {
          completed.set(pending.start, pending.len);
          advanceCommitted();
        }
        if (onProgress && tried - lastReportTried >= progressEvery) {
          const now = Date.now();
          const rate = ((tried - lastReportTried) * 1000) / Math.max(1, now - lastReport);
          lastReport = now;
          lastReportTried = tried;
          onProgress({ tried, rate });
        }
        assign(worker);
      });
      worker.on('error', (err) => {
        if (!settled) {
          settled = true;
          for (const w of pool) w.terminate();
          reject(err);
        }
      });
    }

    busy = pool.length;
    for (const worker of pool) assign(worker);
  });
}

module.exports = { searchParallel, defaultWorkers };
