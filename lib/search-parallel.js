'use strict';

// Parallel search for AES entries using a worker pool. The main thread pulls
// candidates from the stream, hands out fixed-size batches, and stops every
// worker the moment one reports a hit. Only AES benefits meaningfully (PBKDF2
// is CPU-bound); ZipCrypto stays on the single-threaded path.

const os = require('os');
const path = require('path');
const { Worker } = require('worker_threads');

function defaultWorkers() {
  return Math.max(1, (os.cpus() || []).length || 1);
}

// Returns a Promise<{ found, password, tried, elapsedMs }>.
function searchParallel(entry, candidates, { workers, batchSize = 800, onProgress, progressEvery = 2000, limit } = {}) {
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
    let tried = 0;
    let fed = 0;
    let active = 0;
    let settled = false;
    let lastReport = started;
    let lastReportTried = 0;

    function nextBatch() {
      const batch = [];
      while (batch.length < batchSize) {
        if (limit && fed >= limit) break;
        const r = iter.next();
        if (r.done) break;
        batch.push(r.value);
        fed++;
      }
      return batch.length ? batch : null;
    }

    function finish(result) {
      if (settled) return;
      settled = true;
      for (const w of pool) w.terminate();
      resolve(result);
    }

    function assign(worker) {
      if (settled) return;
      const batch = nextBatch();
      if (!batch) {
        active--;
        if (active === 0) finish({ found: false, password: null, tried, elapsedMs: Date.now() - started });
        return;
      }
      worker.postMessage({ batch });
    }

    for (let i = 0; i < n; i++) {
      let worker;
      try {
        worker = new Worker(path.join(__dirname, 'worker-aes.js'), { workerData: { material } });
      } catch (err) {
        return reject(err);
      }
      pool.push(worker);
      active++;
      worker.on('message', (msg) => {
        if (settled) return;
        if (msg.found) {
          finish({ found: true, password: msg.password, tried: tried + (msg.triedInBatch || 0), elapsedMs: Date.now() - started });
          return;
        }
        tried += msg.tried;
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
      assign(worker);
    }
  });
}

module.exports = { searchParallel, defaultWorkers };
