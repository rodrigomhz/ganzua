'use strict';

// Worker thread: tests batches of candidate passwords against an AES entry.
// The PBKDF2-SHA1 derivation is the bottleneck, so spreading candidates across
// workers scales the throughput roughly with the number of cores.
//
// The crypto material arrives once via workerData; batches of candidate strings
// arrive as messages. For each batch the worker replies either with a hit
// ({ found, password, triedInBatch }) or with { tried } when the batch is
// exhausted, at which point the pool hands it the next batch.

const { parentPort, workerData } = require('worker_threads');
const aes = require('./crypto-aes');

// Restore Buffer semantics (structured clone delivers plain Uint8Arrays).
const m = workerData.material;
const material = {
  strength: m.strength,
  salt: Buffer.from(m.salt),
  verify: Buffer.from(m.verify),
  ciphertext: Buffer.from(m.ciphertext),
  auth: Buffer.from(m.auth),
};

parentPort.on('message', (msg) => {
  const batch = msg.batch;
  for (let i = 0; i < batch.length; i++) {
    if (aes.verifyPassword(material, batch[i])) {
      parentPort.postMessage({ found: true, password: batch[i], triedInBatch: i + 1 });
      return;
    }
  }
  parentPort.postMessage({ found: false, tried: batch.length });
});
