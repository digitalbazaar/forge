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
