#!/usr/bin/env node
// SPDX-License-Identifier: BSD-2-Clause
// No implicit trust: every value below must come from an independent enrollment
// or the verifier's challenge state, never from the evidence being verified.
import { readFileSync } from 'node:fs';
import { createHash, createPublicKey, ECDH, verify } from 'node:crypto';

const order = BigInt('0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551');
const domain = Buffer.from('MFG_PLATFORM_ATTESTATION_V1');
const uuid = Buffer.from('d9f9b15abc1c4d6292a461c43383d473', 'hex');
const purposes = { enrollment: 1, registration: 2, opening: 3 };
function fail(message) { throw new Error(message); }
function hex(s, bytes, name) {
  if (typeof s !== 'string' || !new RegExp(`^[0-9a-fA-F]{${bytes * 2}}$`).test(s)) fail(`${name} must be ${bytes} bytes of hex`);
  return Buffer.from(s, 'hex');
}
function point(bytes, name) {
  try { ECDH.convertKey(Buffer.concat([Buffer.from([4]), bytes]), 'prime256v1'); }
  catch { fail(`${name} is not a valid P-256 point`); }
}
function match(actual, expected, name) { if (!actual.equals(expected)) fail(`${name} mismatch`); }
function uint(b) { return BigInt(`0x${b.toString('hex')}`); }
function run() {
  const [file, purpose, challengeHex, trustedKeyHex, deviceHex, shdrHex, taHex, teeHex] = process.argv.slice(2);
  if (process.argv.length !== 10 || !Object.hasOwn(purposes, purpose)) fail('usage: node verify.mjs EVIDENCE.bin PURPOSE CHALLENGE_HEX TRUSTED_ATTESTATION_PUBKEY_HEX DEVICE_ID_HEX TA_SIGNED_HEADER_MEASUREMENT_HEX TA_RUNTIME_MEASUREMENT_HEX TEE_RUNTIME_MEASUREMENT_HEX');
  const challenge = hex(challengeHex, 32, 'challenge');
  if (challenge.every(v => v === 0)) fail('challenge must be nonzero');
  const trustedKey = hex(trustedKeyHex, 64, 'trusted key');
  const device = hex(deviceHex, 32, 'device ID');
  const shdr = hex(shdrHex, 32, 'signed-header measurement');
  const ta = hex(taHex, 32, 'TA runtime measurement');
  const tee = hex(teeHex, 32, 'TEE runtime measurement');
  point(trustedKey, 'trusted key');
  const evidence = readFileSync(file);
  if (evidence.length !== 442) fail('evidence length mismatch');
  match(evidence.subarray(0, 27), domain, 'domain');
  if (evidence.readUInt16BE(27) !== 1 || evidence.readUInt32BE(29) !== 308 || evidence[33] !== purposes[purpose] || evidence.readUInt16BE(34) !== 0) fail('version, length, purpose or reserved field mismatch');
  match(evidence.subarray(36, 68), challenge, 'challenge');
  match(evidence.subarray(68, 100), device, 'device ID');
  const keyId = createHash('sha256').update(Buffer.from('MFG_ATTESTATION_KEY_V1')).update(Buffer.from([0, 2, 0, 64])).update(trustedKey).digest();
  match(evidence.subarray(100, 132), keyId, 'attestation key ID');
  point(evidence.subarray(132, 196), 'receipt public key');
  match(evidence.subarray(196, 212), uuid, 'caller UUID');
  match(evidence.subarray(212, 244), shdr, 'TA signed-header measurement');
  match(evidence.subarray(244, 276), ta, 'TA runtime measurement');
  match(evidence.subarray(276, 308), tee, 'TEE runtime measurement');
  if (evidence.readUInt16BE(308) !== 2 || evidence.readUInt16BE(310) !== 64 || evidence.readUInt16BE(376) !== 64) fail('algorithm or key/signature length mismatch');
  match(evidence.subarray(312, 376), trustedKey, 'attestation public key');
  const sig = evidence.subarray(378), r = uint(sig.subarray(0, 32)), s = uint(sig.subarray(32));
  if (r < 1n || r >= order || s < 1n || s > order / 2n) fail('signature is not canonical low-s P-256');
  const key = createPublicKey({ key: { kty: 'EC', crv: 'P-256', x: trustedKey.subarray(0, 32).toString('base64url'), y: trustedKey.subarray(32).toString('base64url') }, format: 'jwk' });
  if (!verify('sha256', evidence.subarray(0, 308), { key, dsaEncoding: 'ieee-p1363' }, sig)) fail('signature mismatch');
  console.log('Evidence verified against the supplied enrollment and challenge.');
}
try { run(); } catch (e) { console.error(`Verification failed: ${e.message}`); process.exitCode = 1; }
