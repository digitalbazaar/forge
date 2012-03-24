var forge = require('../../js/forge');
var fs = require('fs');

p7Pem = fs.readFileSync(__dirname + '/_files/pkcs7.pem', 'ascii');
certPem = fs.readFileSync(__dirname + '/_files/pkcs7_cert.pem', 'ascii');
keyPem = fs.readFileSync(__dirname + '/_files/pkcs7_key.pem', 'ascii');

exports.testMessageFromPem = function(test) {
   p7 = forge.pkcs7.messageFromPem(p7Pem);

   test.equal(p7.type, forge.pki.oids.envelopedData);
   test.equal(p7.version, 0);

   test.equal(p7.recipients.length, 1);
   test.equal(p7.recipients[0].version, 0);
   test.equal(p7.recipients[0].serialNumber, '00d4541c40d835e2f3');

   // Test converted RDN, which is constructed of seven parts.
   test.equal(p7.recipients[0].issuer.length, 7);
   test.equal(p7.recipients[0].issuer[0].type, '2.5.4.6');
   test.equal(p7.recipients[0].issuer[0].value, 'DE');
   test.equal(p7.recipients[0].issuer[1].type, '2.5.4.8');
   test.equal(p7.recipients[0].issuer[1].value, 'Franconia');
   test.equal(p7.recipients[0].issuer[2].type, '2.5.4.7');
   test.equal(p7.recipients[0].issuer[2].value, 'Ansbach');
   test.equal(p7.recipients[0].issuer[3].type, '2.5.4.10');
   test.equal(p7.recipients[0].issuer[3].value, 'Stefan Siegl');
   test.equal(p7.recipients[0].issuer[4].type, '2.5.4.11');
   test.equal(p7.recipients[0].issuer[4].value, 'Geierlein');
   test.equal(p7.recipients[0].issuer[5].type, '2.5.4.3');
   test.equal(p7.recipients[0].issuer[5].value, 'Geierlein DEV');
   test.equal(p7.recipients[0].issuer[6].type, '1.2.840.113549.1.9.1');
   test.equal(p7.recipients[0].issuer[6].value, 'stesie@brokenpipe.de');

   test.equal(p7.recipients[0].encKey.algorithm, '1.2.840.113549.1.1.1');  // RSA
   test.equal(p7.recipients[0].encKey.key.length, 256);

   test.equal(p7.encContent.algorithm, forge.pki.oids['aes256-CBC']);
   test.equal(p7.encContent.parameter.data.length, 16);  // IV

   test.done();
}

exports.testFindRecipient = function(test) {
   p7 = forge.pkcs7.messageFromPem(p7Pem);
   cert = forge.pki.certificateFromPem(certPem);

   ri = p7.findRecipient(cert);
   test.equal(ri.serialNumber, '00d4541c40d835e2f3');

   // Modify certificate so it doesn't match recipient any longer
   cert.serialNumber = '1234567890abcdef42';
   ri = p7.findRecipient(cert);
   test.equal(ri, undefined);

   test.done();
}

exports.testDecrypt = function(test) {
   p7 = forge.pkcs7.messageFromPem(p7Pem);
   privKey = forge.pki.privateKeyFromPem(keyPem);
   p7.decrypt(p7.recipients[0], privKey);

   // symmetric key must be 32 bytes long (AES 256 key)
   test.equal(p7.encContent.key.data.length, 32);
   test.equal(p7.content, 'Today is Boomtime, '
      + "the 9th day of Discord in the YOLD 3178\r\n");

   test.done();
}
