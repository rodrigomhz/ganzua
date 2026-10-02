'use strict';

// Driver paralelo del ataque de texto plano ZipCrypto. La reducción Z se hace
// una vez en el hilo principal; las candidatas Z[2,32) resultantes se reparten
// en lotes entre un pool de workers y se detiene todo en cuanto uno recupera
// las claves.

const os = require('os');
const path = require('path');
const { Worker } = require('worker_threads');
const { makeData, zreduction } = require('./zipcrypto-attack');

function defaultWorkers() {
  return Math.max(1, (os.cpus() || []).length || 1);
}

// Devuelve Promise<[x,y,z] | null>.
function recoverKeysParallel(
  ciphertext,
  plaintext,
  offsetArg = 0,
  { workers, batchSize = 512, onProgress, onZreduce } = {},
) {
  const data = makeData(ciphertext, plaintext, offsetArg);
  const { candidates, index } = zreduction(data.keystream, onZreduce);
  return new Promise((resolve, reject) => {
    const total = candidates.length;
    if (total === 0) return resolve(null);
    const n = Math.max(1, Math.min(workers || defaultWorkers(), Math.ceil(total / batchSize)));

    const pool = [];
    let next = 0;
    let tried = 0;
    let settled = false;
    let busy = 0;

    function finish(result) {
      if (settled) return;
      settled = true;
      for (const w of pool) w.terminate();
      resolve(result);
    }

    function assign(worker) {
      if (settled) return;
      if (next >= total) {
        busy--;
        if (busy === 0) finish(null);
        return;
      }
      const batch = candidates.slice(next, next + batchSize);
      next += batch.length;
      worker.postMessage({ batch });
    }

    const workerData = {
      ciphertext: Buffer.from(ciphertext),
      plaintext: Buffer.from(plaintext),
      offsetArg,
      index,
    };

    for (let i = 0; i < n; i++) {
      let worker;
      try {
        worker = new Worker(path.join(__dirname, 'worker-zc-attack.js'), { workerData });
      } catch (err) {
        for (const w of pool) w.terminate();
        return reject(err);
      }
      pool.push(worker);
      worker.on('message', (msg) => {
        if (settled) return;
        if (msg.found) {
          finish(msg.keys.map((k) => k >>> 0));
          return;
        }
        tried += msg.tried;
        if (onProgress) onProgress(tried, total);
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

module.exports = { recoverKeysParallel, defaultWorkers };
