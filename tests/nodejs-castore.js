var forge = require('../js/forge');

var keyPair1 = forge.pki.rsa.generateKeyPair(1024);
var keyPair2 = forge.pki.rsa.generateKeyPair(1024);
var keyPair3 = forge.pki.rsa.generateKeyPair(2048);

var ca1 = forge.pki.createCertificate();
var ca2 = forge.pki.createCertificate();
var ca3 = forge.pki.createCertificate();


ca1.publicKey = keyPair1.publicKey;
ca2.publicKey = keyPair2.publicKey;
ca3.publicKey = keyPair3.publicKey;

ca1.serialNumber = "01";
ca2.serialNumber = "02";
ca3.serialNumber = "03";

ca1.validity.notBefore = new Date();
ca2.validity.notBefore = new Date();
ca3.validity.notBefore = new Date();

ca1.validity.notAfter = new Date();
ca1.validity.notAfter.setFullYear(ca1.validity.notBefore.getFullYear() + 1);
ca2.validity.notAfter = new Date();
ca2.validity.notAfter.setFullYear(ca2.validity.notBefore.getFullYear() + 2);
ca3.validity.notAfter = new Date();
ca3.validity.notAfter.setFullYear(ca3.validity.notBefore.getFullYear() + 3);

var attrs = [
  {
    name: 'commonName',
    value: 'Cert Authority'
  }
];

var attrs3 = [
  {
    name: 'commonName',
    value: "Other Cert Authority"
  },
  {
    name: 'countryName',
    value: 'CO'
  },
  {
    shortName: 'ST',
    value: "Antioquia"
  },
  {
    shortName: "L",
    value: "Medellin"
  }
];

// note that both CAs 1 and 2 have the same subject distinguished name
ca1.setSubject(attrs);
ca2.setSubject(attrs);

ca3.setSubject(attrs3);


ca1.setExtensions([
  {
    name: 'basicConstraints',
    cA: true,
    pathLenConstraint: 4
  }, {
    name: 'keyUsage',
    keyCertSign: true,
    digitalSignature: true,
    nonRepudiation: true,
    keyEncipherment: true,
    dataEncipherment: true
  }
]);

ca2.setExtensions([
  {
    name: 'basicConstraints',
    cA: true,
    pathLenConstraint: 2
  }, {
    name: 'keyUsage',
    keyCertSign: true,
    digitalSignature: true
  }
]);

ca1.setExtensions([
  {
    name: 'basicConstraints',
    cA: true
  }, {
    name: 'keyUsage',
    keyCertSign: true,
    digitalSignature: true,
    nonRepudiation: true,
  }
]);

ca1.sign(keyPair1.privateKey);
ca2.sign(keyPair2.privateKey);
ca3.sign(keyPair3.privateKey);

var caStore = forge.pki.createCaStore();

caStore.addCertificate(ca1);
console.log("added ca1 to caStore");
caStore.addCertificate(ca2);
console.log("added ca2 to caStore");

console.log("caStore has ca1:", caStore.hasCertificate(ca1));
console.log("caStore has ca2:", caStore.hasCertificate(ca2));
console.log("caStore has ca3:", caStore.hasCertificate(ca3));
console.log("number of certs in caStore:", caStore.listAllCertificates().length);

caStore.addCertificate(ca3);
console.log("added ca3 to caStore");

console.log("caStore has ca1:", caStore.hasCertificate(ca1));
console.log("caStore has ca2:", caStore.hasCertificate(ca2));
console.log("caStore has ca3:", caStore.hasCertificate(ca3));
console.log("number of certs in caStore:", caStore.listAllCertificates().length);

caStore.removeCertificate(ca2);
console.log("removed ca2 from caStore");

console.log("caStore has ca1:", caStore.hasCertificate(ca1));
console.log("caStore has ca2:", caStore.hasCertificate(ca2));
console.log("caStore has ca3:", caStore.hasCertificate(ca3));
console.log("number of certs in caStore:", caStore.listAllCertificates().length);

caStore.removeCertificate(ca1);
console.log("removed ca1 from caStore");

console.log("caStore has ca1:", caStore.hasCertificate(ca1));
console.log("caStore has ca2:", caStore.hasCertificate(ca2));
console.log("caStore has ca3:", caStore.hasCertificate(ca3));
console.log("number of certs in caStore:", caStore.listAllCertificates().length);

caStore.addCertificate(ca3);
console.log("tried to add ca3 to store even though its already there");

console.log("caStore has ca1, using PEM cert string:",
            caStore.hasCertificate(forge.pki.certificateToPem(ca1)));
console.log("caStore has ca2, using PEM cert string:",
            caStore.hasCertificate(forge.pki.certificateToPem(ca2)));
console.log("caStore has ca3, using PEM cert string:",
            caStore.hasCertificate(forge.pki.certificateToPem(ca3)));
console.log("number of certs in caStore:", caStore.listAllCertificates().length);


console.log("tried to remove ca1 from caStore even though its not there, result:",
            caStore.removeCertificate(ca1));

caStore.addCertificate(forge.pki.certificateToPem(ca2));
console.log("added ca2 to caStore as PEM string");

console.log("caStore has ca1:", caStore.hasCertificate(ca1));
console.log("caStore has ca2:", caStore.hasCertificate(ca2));
console.log("caStore has ca3:", caStore.hasCertificate(ca3));
console.log("number of certs in caStore:", caStore.listAllCertificates().length);

caStore.removeCertificate(forge.pki.certificateToPem(ca3));
console.log("removed ca3 from caStore as a PEM string");

console.log("caStore has ca1:", caStore.hasCertificate(ca1));
console.log("caStore has ca2:", caStore.hasCertificate(ca2));
console.log("caStore has ca3:", caStore.hasCertificate(ca3));
console.log("number of certs in caStore:", caStore.listAllCertificates().length);

console.log("In the end, the caStore should just have one certificate: ca2");

