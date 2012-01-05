var forge = require('../js/forge');

console.log('Generating 1024-bit key-pair...');
var keys = forge.pki.rsa.generateKeyPair(1024);
console.log('Key-pair created.');

console.log('Creating self-signed certificate...');
var cert = forge.pki.createCertificate();
cert.serialNumber = '01';
cert.validity.notBefore = new Date();
cert.validity.notAfter = new Date();
cert.validity.notAfter.setFullYear(cert.validity.notBefore.getFullYear() + 1);
var attrs = [{
  name: 'commonName',
  value: 'example.org'
}, {
  name: 'countryName',
  value: 'US'
}, {
  shortName: 'ST',
  value: 'Virginia'
}, {
  name: 'localityName',
  value: 'Blacksburg'
}, {
  name: 'organizationName',
  value: 'Test'
}, {
  shortName: 'OU',
  value: 'Test'
}];
cert.setSubject(attrs);
cert.setIssuer(attrs);
cert.setExtensions([{
  name: 'basicConstraints',
  cA: true
}, {
  name: 'keyUsage',
  keyCertSign: true,
  digitalSignature: true,
  nonRepudiation: true,
  keyEncipherment: true,
  dataEncipherment: true
}, {
  name: 'subjectAltName',
  altNames: [{
    type: 6, // URI
    value: 'http://example.org/webid#me'
  }]
}]);
// FIXME: add subjectKeyIdentifier extension
// FIXME: add authorityKeyIdentifier extension
cert.publicKey = keys.publicKey;

// self-sign certificate
cert.sign(keys.privateKey);
console.log('Certificate created.');

// PEM-format keys and cert
var pem = {
  privateKey: forge.pki.privateKeyToPem(keys.privateKey),
  publicKey: forge.pki.publicKeyToPem(keys.publicKey),
  certificate: forge.pki.certificateToPem(cert)
};

console.log('\nKey-Pair:');
console.log(pem.privateKey);
console.log(pem.publicKey);

console.log('\nCertificate:');
console.log(pem.certificate);

// verify certificate
var caStore = forge.pki.createCaStore();
caStore.addCertificate(cert);
try {
  forge.pki.verifyCertificateChain(caStore, [cert],
    function(vfd, depth, chain) {
      if(vfd === true) {
        console.log('Certificate verified.');
      }
      return true;
  });
}
catch(ex) {
  console.log('Certificate verification failure: ' +
    JSON.stringify(ex, null, 2));
}
