'use strict';

// Worker para el ataque de texto plano ZipCrypto: recibe lotes de candidatas
// Z[2,32) y ejecuta el núcleo del ataque sobre cada lote. El reparto de
// candidatas escala el ataque con el número de núcleos.

const { parentPort, workerData } = require('worker_threads');
const { makeData, runAttack } = require('./zipcrypto-attack');

const ciphertext = Buffer.from(workerData.ciphertext);
const plaintext = Buffer.from(workerData.plaintext);
const data = makeData(ciphertext, plaintext, workerData.offsetArg);
const index = workerData.index;

parentPort.on('message', (msg) => {
  const keys = runAttack(data, msg.batch, index);
  if (keys) parentPort.postMessage({ found: true, keys });
  else parentPort.postMessage({ found: false, tried: msg.batch.length });
});
