var forge = require('../../js/forge');
var fs = require('fs');

// We simply put the pkcs7 test files into PKCS#12 PFX file
var certPem = fs.readFileSync(__dirname + '/_files/pkcs7_cert.pem', 'ascii');
var keyPem = fs.readFileSync(__dirname + '/_files/pkcs7_key.pem', 'ascii');

function mockRandomGetBytes(num) {
  var bb = new forge.util.ByteBuffer();
  bb.fillWithByte(0, num);
  return bb.getBytes();
}

exports.testToPkcs12Asn1_CertOnly = function(test) {
  var cert = forge.pki.certificateFromPem(certPem);
  var p12Asn = forge.pkcs12.toPkcs12Asn1(null, cert, null);
  var p12Der = forge.asn1.toDer(p12Asn).getBytes();

  /* The generated PKCS#12 file lacks a MAC, therefore pass -nomacver to
     OpenSSL like so:  openssl pkcs12 -nomacver -in _files/pkcs12_certonly.p12 */
  var exp = fs.readFileSync(__dirname + '/_files/pkcs12_certonly.p12', 'binary');

  test.equal(p12Der, exp);
  test.done();
};

exports.testToPkcs12Asn1_KeyOnly = function(test) {
  var privKey = forge.pki.privateKeyFromPem(keyPem);
  var p12Asn = forge.pkcs12.toPkcs12Asn1(privKey, null, null);
  var p12Der = forge.asn1.toDer(p12Asn).getBytes();

  /* The generated PKCS#12 file lacks a MAC, therefore pass -nomacver to
     OpenSSL like so:  openssl pkcs12 -nomacver -nodes -in _files/pkcs12_keyonly.p12 */
  var exp = fs.readFileSync(__dirname + '/_files/pkcs12_keyonly.p12', 'binary');
  test.equal(p12Der, exp);
  test.done();
};

exports.testToPkcs12Asn1_EncryptedKeyOnly = function(test) {
  /* We need to mock the PRNG, since the PKCS#12 file uses encryption which
     otherwise would differ from time to time due to the included IV. */
  var origRandomGetBytes = forge.random.getBytes;
  forge.random.getBytes = mockRandomGetBytes;

  var privKey = forge.pki.privateKeyFromPem(keyPem);
  var p12Asn = forge.pkcs12.toPkcs12Asn1(privKey, null, 'nopass');
  var p12Der = forge.asn1.toDer(p12Asn).getBytes();

  /* The generated PKCS#12 file lacks a MAC, therefore pass -nomacver to
     OpenSSL like so:  openssl pkcs12 -nomacver -nodes -in _files/pkcs12_enckeyonly.p12 */
  var exp = fs.readFileSync(__dirname + '/_files/pkcs12_enckeyonly.p12', 'binary');
  test.equal(p12Der, exp);
  test.done();

  /* Restore original forge PRNG. */
  forge.random.getBytes = origRandomGetBytes;
};

exports.testPkcs12FromAsn1_PlainCertOnly = function(test) {
  var p12Der = fs.readFileSync(__dirname + '/_files/pkcs12_certonly.p12', 'binary');
  var p12Asn1 = forge.asn1.fromDer(p12Der);
  var p12 = forge.pkcs12.pkcs12FromAsn1(p12Asn1);

  /* The PKCS#12 PFX has exactly on SafeContents instance,
     and it is not encrypted. */
  test.equals(p12.version, 3);
  test.equals(p12.safeContents.length, 1);
  test.equals(p12.safeContents[0].encrypted, false);

  /* The SafeContents instance is expected to hold on SafeBag, which
     holds a CertBag with the X.509 certificate. */
  test.equals(p12.safeContents[0].safeBags.length, 1);
  test.equals(p12.safeContents[0].safeBags[0].type, forge.pki.oids.certBag);

  /* Check X.509 certificate's serial number to be sure it has been read. */
  test.equals(p12.safeContents[0].safeBags[0].cert.serialNumber, '00d4541c40d835e2f3');
  test.done();
};

exports.testPkcs12FromAsn1_PlainKeyOnly = function(test) {
  var p12Der = fs.readFileSync(__dirname + '/_files/pkcs12_keyonly.p12', 'binary');
  var p12Asn1 = forge.asn1.fromDer(p12Der);

  var p12 = forge.pkcs12.pkcs12FromAsn1(p12Asn1);

  /* The PKCS#12 PFX has exactly on SafeContents instance,
     and it is not encrypted. */
  test.equals(p12.version, 3);
  test.equals(p12.safeContents.length, 1);
  test.equals(p12.safeContents[0].encrypted, false);

  /* The SafeContents instance is expected to hold on SafeBag, which
     holds a KeyBag with the private key. */
  test.equals(p12.safeContents[0].safeBags.length, 1);
  test.equals(p12.safeContents[0].safeBags[0].type, forge.pki.oids.keyBag);

  /* Compare the key from the PFX by simply comparing both primes. */
  var expKey = forge.pki.privateKeyFromPem(keyPem);
  test.deepEqual(p12.safeContents[0].safeBags[0].key.p, expKey.p);
  test.deepEqual(p12.safeContents[0].safeBags[0].key.q, expKey.q);

  test.done();
};

exports.testPkcs12FromAsn1_EncryptedKeyOnly = function(test) {
  var p12Der = fs.readFileSync(__dirname + '/_files/pkcs12_enckeyonly.p12', 'binary');
  var p12Asn1 = forge.asn1.fromDer(p12Der);
  var p12 = forge.pkcs12.pkcs12FromAsn1(p12Asn1, 'nopass');

  /* The PKCS#12 PFX has exactly on SafeContents instance,
     and it is *not* encrypted.  Only the key itself is crypted (shrouded) */
  test.equals(p12.version, 3);
  test.equals(p12.safeContents.length, 1);
  test.equals(p12.safeContents[0].encrypted, false);

  /* The SafeContents instance is expected to hold on SafeBag, which
     holds a KeyBag with the private key. */
  test.equals(p12.safeContents[0].safeBags.length, 1);
  test.equals(p12.safeContents[0].safeBags[0].type, forge.pki.oids.pkcs8ShroudedKeyBag);

  /* Compare the key from the PFX by simply comparing both primes. */
  var expKey = forge.pki.privateKeyFromPem(keyPem);
  test.deepEqual(p12.safeContents[0].safeBags[0].key.p, expKey.p);
  test.deepEqual(p12.safeContents[0].safeBags[0].key.q, expKey.q);

  test.done();
};

exports.testGenerateKey = function(test) {
  var salt = 'A15D6AA8F8DAFC352F9EE1C192F09966EB85D17B';
  salt = new forge.util.ByteBuffer(forge.util.hexToBytes(salt));

  var exp = '03e46727268575c6ebd6bff828d0d09b0c914201263ca543';
  var gen = forge.pkcs12.generateKey('123456', salt, 1, 1024, 24);
  test.equals(gen.toHex(), exp);
  test.done();
};

