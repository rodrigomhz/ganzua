'use strict';

// Ataque de texto plano conocido de Biham-Kocher contra ZipCrypto, nativo en
// JavaScript. Port fiel del algoritmo de bkcrack (kimci86/bkcrack, v1.8.1):
//   - Zreduction: genera y reduce candidatas Z[10,32) con el keystream.
//   - Attack: por cada Z[2,32), recupera Z, Y y X y valida.
// Con ~12 bytes de texto plano conocido (8 contiguos) recupera las claves
// internas (x, y, z) y descifra todo el archivo sin la contraseña.
//
// Referencia: M. Stay, "ZIP Attacks with Reduced Known Plaintext"; A. Biham,
// P. Kocher, "A Known Plaintext Attack on the PKZIP Stream Cipher".

const { CRC_TABLE, CRC_INV_TABLE, MULTINV, Keys } = require('./crypto-zipcrypto');

// --- máscaras y constantes --------------------------------------------------
const MASK_2_32 = 0xfffffffc;
const MASK_8_32 = 0xffffff00;
const MASK_10_32 = 0xfffffc00;
const MASK_24_32 = 0xff000000;
const MASK_26_32 = 0xfc000000;
const MAXDIFF_24 = 0x00ffffff + 0xff; // mask<0,24> + 0xff
const MAXDIFF_26 = 0x03ffffff + 0xff; // mask<0,26> + 0xff
const CONTIGUOUS_SIZE = 8;
const ATTACK_SIZE = 12;
const HEADER_SIZE = 12;

const lsb = (x) => x & 0xff;
const msb = (x) => x >>> 24;
const crc32 = (pval, b) => ((pval >>> 8) ^ CRC_TABLE[(pval & 0xff) ^ b]) >>> 0;
const crc32inv = (crc, b) => (((crc << 8) >>> 0) ^ CRC_INV_TABLE[crc >>> 24] ^ b) >>> 0;
const getYi_24_32 = (zi, zim1) => ((crc32inv(zi, 0) ^ zim1) << 24) >>> 0;
const getZim1_10_32 = (zi_2_32) => (crc32inv(zi_2_32, 0) & MASK_10_32) >>> 0;

// --- tablas de keystream (como bkcrack KeystreamTab) ------------------------
const keystreamtab = new Uint8Array(1 << 14);
const keystreaminvfiltertab = Array.from({ length: 256 }, () => Array.from({ length: 64 }, () => []));
const keystreaminvexists = Array.from({ length: 256 }, () => new Uint8Array(64));
for (let z = 0; z < 1 << 16; z += 4) {
  const k = (((z | 2) * (z | 3)) >>> 8) & 0xff;
  keystreamtab[z >> 2] = k;
  keystreaminvfiltertab[k][z >> 10].push(z);
  keystreaminvexists[k][z >> 10] = 1;
}
const getZiVec = (ki, zi_10_16) => keystreaminvfiltertab[ki][(zi_10_16 & 0xffff) >>> 10];
const hasZi = (ki, zi_10_16) => keystreaminvexists[ki][(zi_10_16 & 0xffff) >>> 10];

// --- tablas de multiplicación (como bkcrack MultTab) ------------------------
const msbprodfiber2 = Array.from({ length: 256 }, () => []);
const msbprodfiber3 = Array.from({ length: 256 }, () => []);
{
  let prodinv = 0;
  for (let x = 0; x < 256; x++) {
    const m = prodinv >>> 24;
    msbprodfiber2[m].push(x);
    msbprodfiber2[(m + 1) & 0xff].push(x);
    msbprodfiber3[(m + 255) & 0xff].push(x);
    msbprodfiber3[m].push(x);
    msbprodfiber3[(m + 1) & 0xff].push(x);
    prodinv = (prodinv + MULTINV) >>> 0;
  }
}

// --- Data: keystream a partir de texto plano y cifrado ----------------------
function makeData(ciphertext, plaintext, offsetArg = 0) {
  if (ciphertext.length < ATTACK_SIZE) throw new Error(`cifrado demasiado corto (mínimo ${ATTACK_SIZE} bytes)`);
  if (plaintext.length < CONTIGUOUS_SIZE) {
    throw new Error(`texto plano insuficiente (${plaintext.length} bytes, mínimo ${CONTIGUOUS_SIZE} contiguos)`);
  }
  if (plaintext.length < ATTACK_SIZE) {
    throw new Error(`texto plano insuficiente (${plaintext.length} bytes, mínimo ${ATTACK_SIZE})`);
  }
  if (offsetArg < -HEADER_SIZE) throw new Error(`offset ${offsetArg} demasiado pequeño`);
  const offset = HEADER_SIZE + offsetArg;
  if (ciphertext.length < offset + plaintext.length) throw new Error(`offset ${offsetArg} demasiado grande`);
  const keystream = new Uint8Array(plaintext.length);
  for (let i = 0; i < plaintext.length; i++) keystream[i] = (plaintext[i] ^ ciphertext[offset + i]) & 0xff;
  return { ciphertext, plaintext, keystream, offset };
}

// --- Zreduction -------------------------------------------------------------
function zreduction(keystream, progress) {
  let index = keystream.length - 1;

  // Estado inicial: Z[10,32) compatibles con el último byte de keystream.
  let ziVec = [];
  const kLast = keystream[index];
  for (let s = 0; s < 1 << 22; s++) {
    const z = (s << 10) >>> 0;
    if (hasZi(kLast, z)) ziVec.push(z);
  }

  if (keystream.length > CONTIGUOUS_SIZE) {
    const seen = new Uint32Array(1 << 17); // bitset de 2^22 bits
    let tracking = false;
    let bestCopy = null;
    let bestIndex = index;
    let bestSize = 1 << 16;
    let waiting = false;
    let wait = 0;

    for (let i = index; i >= CONTIGUOUS_SIZE; i--) {
      seen.fill(0);
      const next = [];
      let count = 0;
      const ki = keystream[i];
      const kim1 = keystream[i - 1];
      for (let vi = 0; vi < ziVec.length; vi++) {
        const zi_10_32 = ziVec[vi];
        const vec = getZiVec(ki, zi_10_32);
        for (let j = 0; j < vec.length; j++) {
          const zim1_10_32 = getZim1_10_32((zi_10_32 | vec[j]) >>> 0);
          const bit = zim1_10_32 >>> 10;
          const w = bit >>> 5;
          const m = (1 << (bit & 31)) >>> 0;
          if (!(seen[w] & m) && hasZi(kim1, zim1_10_32)) {
            next.push(zim1_10_32);
            seen[w] |= m;
            count += getZiVec(kim1, zim1_10_32).length;
          }
        }
      }

      if (count <= bestSize) {
        tracking = true;
        bestIndex = i - 1;
        bestSize = count;
        waiting = false;
      } else if (tracking) {
        if (bestIndex === i) {
          bestCopy = ziVec;
          if (bestSize <= 1 << 8) {
            waiting = true;
            wait = bestSize * 4;
          }
        }
        if (waiting && --wait === 0) break;
      }
      ziVec = next;
      if (progress) progress(index - i + 1, keystream.length - CONTIGUOUS_SIZE);
    }

    if (tracking) {
      if (bestIndex !== CONTIGUOUS_SIZE - 1) ziVec = bestCopy;
      index = bestIndex;
    } else {
      index = CONTIGUOUS_SIZE - 1;
    }
  }

  // Generar Z[2,32) a partir de Z[10,32).
  const candidates = [];
  const ki = keystream[index];
  for (let vi = 0; vi < ziVec.length; vi++) {
    const vec = getZiVec(ki, ziVec[vi]);
    for (let j = 0; j < vec.length; j++) candidates.push((ziVec[vi] | vec[j]) >>> 0);
  }
  return { candidates, index };
}

// --- Attack -----------------------------------------------------------------
function runAttack(data, candidates, zrIndex, onProgress) {
  const { ciphertext, plaintext, keystream, offset } = data;
  const index = zrIndex + 1 - CONTIGUOUS_SIZE;
  const zlist = new Uint32Array(8);
  const ylist = new Uint32Array(8);
  const xlist = new Uint32Array(8);
  let solution = null;

  function testXlist() {
    for (let i = 5; i <= 7; i++) {
      xlist[i] = ((crc32(xlist[i - 1], plaintext[index + i - 1]) & MASK_8_32) | lsb(xlist[i])) >>> 0;
    }
    let x = xlist[7];
    for (let i = 6; i >= 3; i--) x = crc32inv(x, plaintext[index + i]);

    const y1_26_32 = (getYi_24_32(zlist[1], zlist[0]) & MASK_26_32) >>> 0;
    let t = Math.imul((ylist[3] - 1) >>> 0, MULTINV) >>> 0;
    t = (t - lsb(x)) >>> 0;
    t = Math.imul((t - 1) >>> 0, MULTINV) >>> 0;
    t = (t - y1_26_32) >>> 0;
    if (t > MAXDIFF_26) return;

    // filtro hacia delante
    const kf = Keys.fromState(xlist[7], ylist[7], zlist[7]);
    kf.update(plaintext[index + 7]);
    for (let p = index + 8, c = offset + index + 8; p < plaintext.length; p++, c++) {
      if (((ciphertext[c] ^ kf.getK()) & 0xff) !== plaintext[p]) return;
      kf.update(plaintext[p]);
    }

    // filtro hacia atrás
    const kb = Keys.fromState(x, ylist[3], zlist[3]);
    for (let p = index + 2, c = offset + index + 2; p >= 0; p--, c--) {
      kb.updateBackward(ciphertext[c]);
      if (((ciphertext[c] ^ kb.getK()) & 0xff) !== plaintext[p]) return;
    }

    // retroceder hasta el estado inicial (posición 0)
    kb.updateBackwardRange(ciphertext, offset, 0);
    solution = [kb.k0, kb.k1, kb.k2];
  }

  function exploreYlists(i) {
    if (solution) return;
    if (i !== 3) {
      const fy = Math.imul((ylist[i] - 1) >>> 0, MULTINV) >>> 0;
      const ffy = Math.imul((fy - 1) >>> 0, MULTINV) >>> 0;
      const fiber = msbprodfiber2[((ffy - (ylist[i - 2] & MASK_24_32)) >>> 0) >>> 24];
      for (let fi = 0; fi < fiber.length; fi++) {
        const xi = fiber[fi];
        const yim1 = (fy - xi) >>> 0;
        const d = (((ffy - (Math.imul(MULTINV, xi) >>> 0)) >>> 0) - (ylist[i - 2] & MASK_24_32)) >>> 0;
        if (d <= MAXDIFF_24 && msb(yim1) === msb(ylist[i - 1])) {
          ylist[i - 1] = yim1;
          xlist[i] = xi;
          exploreYlists(i - 1);
          if (solution) return;
        }
      }
    } else {
      testXlist();
    }
  }

  function exploreZlists(i) {
    if (solution) return;
    if (i !== 0) {
      const zim1_10_32 = getZim1_10_32(zlist[i]);
      const vec = getZiVec(keystream[index + i - 1], zim1_10_32);
      for (let vi = 0; vi < vec.length; vi++) {
        zlist[i - 1] = (zim1_10_32 | vec[vi]) >>> 0;
        zlist[i] = (zlist[i] & MASK_2_32) >>> 0;
        zlist[i] = (zlist[i] | ((crc32inv(zlist[i], 0) ^ zlist[i - 1]) >>> 8)) >>> 0;
        if (i < 7) ylist[i + 1] = getYi_24_32(zlist[i + 1], zlist[i]);
        exploreZlists(i - 1);
        if (solution) return;
      }
    } else {
      let prod = (((Math.imul(MULTINV, msb(ylist[7])) << 24) >>> 0) - MULTINV) >>> 0;
      const step = (MULTINV << 8) >>> 0;
      for (let y7_8_24 = 0; y7_8_24 < 1 << 24; y7_8_24 += 1 << 8) {
        const fiber = msbprodfiber3[(msb(ylist[6]) - (prod >>> 24)) & 0xff];
        for (let fi = 0; fi < fiber.length; fi++) {
          const y7_0_8 = fiber[fi];
          const d = (((prod + (Math.imul(MULTINV, y7_0_8) >>> 0)) >>> 0) - (ylist[6] & MASK_24_32)) >>> 0;
          if (d <= MAXDIFF_24) {
            ylist[7] = (y7_0_8 | y7_8_24 | (ylist[7] & MASK_24_32)) >>> 0;
            exploreYlists(7);
            if (solution) return;
          }
        }
        prod = (prod + step) >>> 0;
      }
    }
  }

  for (let ci = 0; ci < candidates.length; ci++) {
    zlist[7] = candidates[ci] >>> 0;
    exploreZlists(7);
    if (solution) return solution;
    if (onProgress && (ci & 0x3ff) === 0) onProgress(ci, candidates.length);
  }
  return null;
}

// Recupera las claves internas (x, y, z) a partir de cifrado + texto plano.
// `ciphertext` incluye la cabecera de cifrado de 12 bytes. Devuelve [x,y,z] o
// null si no se encuentra.
function recoverKeys(ciphertext, plaintext, offsetArg = 0, { onZreduce, onAttack } = {}) {
  const data = makeData(ciphertext, plaintext, offsetArg);
  const { candidates, index } = zreduction(data.keystream, onZreduce);
  return runAttack(data, candidates, index, onAttack);
}

// Conveniencia: ataca una entrada ZipCrypto (header+body) con texto plano
// conocido del flujo cifrado.
function attackEntry(entryCrypto, plaintext, offsetArg = 0, hooks) {
  const ciphertext = Buffer.concat([entryCrypto.header, entryCrypto.body]);
  return recoverKeys(ciphertext, plaintext, offsetArg, hooks);
}

module.exports = { recoverKeys, attackEntry, makeData, zreduction, runAttack, CONTIGUOUS_SIZE, ATTACK_SIZE };
