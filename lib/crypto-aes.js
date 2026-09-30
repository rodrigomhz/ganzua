'use strict';

// WinZip AES (AE-1 / AE-2) verification and decryption.
//
// Layout of the file data for an AES entry:
//   [ salt ][ 2-byte password verifier ][ ciphertext ][ 10-byte auth code ]
// Salt length depends on the key strength:
//   1 => AES-128 (8 B salt), 2 => AES-192 (12 B), 3 => AES-256 (16 B).
//
// Key derivation (per entry):
//   PBKDF2-HMAC-SHA1(password, salt, 1000 iterations, 2*keyLen + 2 bytes)
//     -> encKey (keyLen) | macKey (keyLen) | pwdVerify (2)
// The 2-byte pwdVerify must match the stored verifier (fast 1/65536 reject).
// Definitive check: HMAC-SHA1(macKey, ciphertext)[0..10) == stored auth code.

const crypto = require('crypto');
const { toBytes } = require('./encoding');

const ITERATIONS = 1000;
const PBKDF2_DIGEST = 'sha1';

// strength byte -> { keyLen, saltLen, bits }
const STRENGTH = {
  1: { keyLen: 16, saltLen: 8, bits: 128 },
  2: { keyLen: 24, saltLen: 12, bits: 192 },
  3: { keyLen: 32, saltLen: 16, bits: 256 },
};

function paramsForStrength(strength) {
  const p = STRENGTH[strength];
  if (!p) throw new Error(`fuerza AES desconocida: ${strength}`);
  return p;
}

// Derive the per-password key material for an entry.
function deriveKeys(password, salt, keyLen, encoding = 'utf8') {
  const pw = toBytes(password, encoding);
  const dk = crypto.pbkdf2Sync(pw, salt, ITERATIONS, keyLen * 2 + 2, PBKDF2_DIGEST);
  return {
    encKey: dk.subarray(0, keyLen),
    macKey: dk.subarray(keyLen, keyLen * 2),
    pwdVerify: dk.subarray(keyLen * 2, keyLen * 2 + 2),
  };
}

// Fast reject: does the derived 2-byte verifier match the stored one?
function verifierMatches(derivedVerify, storedVerify) {
  return derivedVerify[0] === storedVerify[0] && derivedVerify[1] === storedVerify[1];
}

// Definitive: does HMAC-SHA1(macKey, ciphertext)[0..10) match the stored auth code?
function authMatches(macKey, ciphertext, storedAuth) {
  const mac = crypto.createHmac('sha1', macKey).update(ciphertext).digest();
  return mac.subarray(0, 10).equals(storedAuth);
}

// Test a candidate password against an AES entry.
//   entry: { strength, salt, verify, ciphertext, auth }
// Returns true only when the password is definitively correct.
//
// Two modes:
//  - fast=false (default): verifier check, then HMAC confirmation. Zero false
//    positives. Requires the ciphertext + auth to be present.
//  - fast=true: verifier check only (1/65536 false-positive rate). Used as a
//    cheap pre-filter; callers must confirm with HMAC before trusting a hit.
function verifyPassword(entry, password, { fast = false, encoding = 'utf8' } = {}) {
  const { keyLen } = paramsForStrength(entry.strength);
  const { macKey, pwdVerify } = deriveKeys(password, entry.salt, keyLen, encoding);
  if (!verifierMatches(pwdVerify, entry.verify)) return false;
  if (fast) return true;
  return authMatches(macKey, entry.ciphertext, entry.auth);
}

// AES-CTR keystream decryption as used by WinZip AES: a 16-byte little-endian
// block counter starting at 1, AES-ECB of the counter XORed with the data.
function ctrDecrypt(encKey, ciphertext, keyLen) {
  const cipherName = `aes-${keyLen * 8}-ecb`;
  const out = Buffer.allocUnsafe(ciphertext.length);
  const counter = Buffer.alloc(16);
  let block = 1n;
  for (let i = 0; i < ciphertext.length; i += 16) {
    let c = block;
    for (let b = 0; b < 16; b++) {
      counter[b] = Number(c & 0xffn);
      c >>= 8n;
    }
    const ecb = crypto.createCipheriv(cipherName, encKey, null);
    ecb.setAutoPadding(false);
    const ks = Buffer.concat([ecb.update(counter), ecb.final()]);
    const end = Math.min(i + 16, ciphertext.length);
    for (let b = 0; i + b < end; b++) out[i + b] = ciphertext[i + b] ^ ks[b];
    block += 1n;
  }
  return out;
}

// Decrypt an entry's ciphertext with a known-correct password. Returns the
// raw (still possibly DEFLATE-compressed) bytes; the caller inflates if needed.
function decrypt(entry, password, encoding = 'utf8') {
  const { keyLen } = paramsForStrength(entry.strength);
  const { encKey } = deriveKeys(password, entry.salt, keyLen, encoding);
  return ctrDecrypt(encKey, entry.ciphertext, keyLen);
}

module.exports = {
  ITERATIONS,
  STRENGTH,
  paramsForStrength,
  deriveKeys,
  verifierMatches,
  authMatches,
  verifyPassword,
  ctrDecrypt,
  decrypt,
};
