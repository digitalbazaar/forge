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

   test.equal(p7.recipients[0].encContent.algorithm, '1.2.840.113549.1.1.1');  // RSA
   test.equal(p7.recipients[0].encContent.content.length, 256);

   test.equal(p7.encContent.algorithm, forge.pki.oids['aes256-CBC']);
   test.equal(p7.encContent.parameter.data.length, 16);  // IV

   test.done();
}

exports.testMessageFromPemWithIndefLength = function(test) {
   var p7Pem = fs.readFileSync(__dirname + '/_files/pkcs7_indef.pem', 'ascii');
   test.expect(3);

   try {
      p7 = forge.pkcs7.messageFromPem(p7Pem);
      test.equal(p7.type, forge.pki.oids.envelopedData);
      test.equal(p7.encContent.parameter.toHex(), '536da6a06653733d');
      test.equal(p7.encContent.content.length(), 80);
   } catch(err) {
      console.log('Caught messageFromPem error:', err);
   }

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

exports.testDecryptAES = function(test) {
   p7 = forge.pkcs7.messageFromPem(p7Pem);
   privKey = forge.pki.privateKeyFromPem(keyPem);
   p7.decrypt(p7.recipients[0], privKey);

   // symmetric key must be 32 bytes long (AES 256 key)
   test.equal(p7.encContent.key.data.length, 32);
   test.equal(p7.content, 'Today is Boomtime, '
      + "the 9th day of Discord in the YOLD 3178\r\n");

   test.done();
}

exports.testDecryptDES = function(test) {
   var p7Pem = fs.readFileSync(__dirname + '/_files/pkcs7_des3.pem', 'ascii');

   p7 = forge.pkcs7.messageFromPem(p7Pem);
   privKey = forge.pki.privateKeyFromPem(keyPem);
   p7.decrypt(p7.recipients[0], privKey);

   // symmetric key must be 24 bytes long (DES3 key)
   test.equal(p7.encContent.key.data.length, 24);
   test.equal(p7.content, 'Today is Prickle-Prickle, '
      + "the 16th day of Discord in the YOLD 3178\r\n");

   test.done();
}

exports.testAddRecipient = function(test) {
   p7 = forge.pkcs7.createEnvelopedData();

   // initially there should be no recipients
   test.equal(p7.recipients.length, 0);

   cert = forge.pki.certificateFromPem(certPem);
   p7.addRecipient(cert);

   test.equal(p7.recipients.length, 1);
   test.deepEqual(p7.recipients[0].serialNumber, cert.serialNumber);
   test.deepEqual(p7.recipients[0].issuer, cert.subject.attributes);
   test.deepEqual(p7.recipients[0].encContent.key, cert.publicKey);

   test.done();
}

exports.testEncrypt = function(test) {
   p7 = forge.pkcs7.createEnvelopedData();
   cert = forge.pki.certificateFromPem(certPem);
   privKey = forge.pki.privateKeyFromPem(keyPem);

   p7.addRecipient(cert);
   p7.content = forge.util.createBuffer('Just a little test');

   // pre-condition, PKCS#7 module should default to AES-256-CBC
   test.equal(p7.encContent.algorithm, forge.pki.oids['aes256-CBC']);
   p7.encrypt();

   // Since we did not provide a key, a random key should have been created
   // automatically.  AES256 requires 32 bytes of key material.
   test.equal(p7.encContent.key.data.length, 32);

   // Furthermore an IV must be generated.  AES256 has 16 bytes IV.
   test.equal(p7.encContent.parameter.data.length, 16);

   // Content is 18 Bytes long, AES has 16 byte blocksize,
   // with padding that should make up 32 bytes.
   test.equals(p7.encContent.content.data.length, 32);

   // RSA encryption should yield 256 bytes
   test.equals(p7.recipients[0].encContent.content.length, 256);

   // rewind Key & IV
   p7.encContent.key.read = 0;
   p7.encContent.parameter.read = 0;

   // decryption of the asym. encrypted data should reveal the symmetric key
   decryptedKey = privKey.decrypt(p7.recipients[0].encContent.content);
   test.equals(decryptedKey, p7.encContent.key.data);

   // decryption of sym. encrypted data should reveal the content
   ciph = forge.aes.createDecryptionCipher(decryptedKey);
   ciph.start(p7.encContent.parameter);   // IV
   ciph.update(p7.encContent.content);
   ciph.finish();
   test.equals(ciph.output, 'Just a little test');

   test.done();
}

exports.testEncryptDES3EDE = function(test) {
   p7 = forge.pkcs7.createEnvelopedData();
   cert = forge.pki.certificateFromPem(certPem);
   privKey = forge.pki.privateKeyFromPem(keyPem);

   p7.addRecipient(cert);
   p7.content = forge.util.createBuffer('Just a little test');
   p7.encContent.algorithm = forge.pki.oids['des-EDE3-CBC'];
   p7.encrypt();

   // Since we did not provide a key, a random key should have been created
   // automatically.  DES3-EDE requires 24 bytes of key material.
   test.equal(p7.encContent.key.data.length, 24);

   // Furthermore an IV must be generated.  DES3 has 8 bytes IV.
   test.equal(p7.encContent.parameter.data.length, 8);

   // Content is 18 Bytes long, DES has 8 byte blocksize,
   // with padding that should make up 24 bytes.
   test.equals(p7.encContent.content.data.length, 24);

   // RSA encryption should yield 256 bytes
   test.equals(p7.recipients[0].encContent.content.length, 256);

   // rewind Key & IV
   p7.encContent.key.read = 0;
   p7.encContent.parameter.read = 0;

   // decryption of the asym. encrypted data should reveal the symmetric key
   decryptedKey = privKey.decrypt(p7.recipients[0].encContent.content);
   test.equals(decryptedKey, p7.encContent.key.data);

   // decryption of sym. encrypted data should reveal the content
   ciph = forge.des.createDecryptionCipher(decryptedKey);
   ciph.start(p7.encContent.parameter);   // IV
   ciph.update(p7.encContent.content);
   ciph.finish();
   test.equals(ciph.output, 'Just a little test');

   test.done();
}

exports.testMessageToPem = function(test) {
   p7 = forge.pkcs7.createEnvelopedData();
   p7.addRecipient(forge.pki.certificateFromPem(certPem));
   p7.content = forge.util.createBuffer('Just a little test');
   p7.encrypt();

   pem = forge.pkcs7.messageToPem(p7);

   // Convert back from PEM to new PKCS#7 object, decrypt and test.
   p7 = forge.pkcs7.messageFromPem(pem);
   p7.decrypt(p7.recipients[0], forge.pki.privateKeyFromPem(keyPem));
   test.equals(p7.content, 'Just a little test');

   test.done();
}
