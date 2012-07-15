var forge = require('../../js/forge');
var fs = require('fs');

/*
 * Test encryption & decryption using RSA with PKCS#1 v1.5 padding
 *
 * We're testing using different key sizes (1024, 1025, 1031, 1032).
 * The test functions are generated from "templates" below, one
 * for each key size to provide sensible output to nodeunit.
 *
 * Key material in _files directory was created with OpenSSL using
 * these commands:
 *
 * openssl genrsa -out rsa_1024_private.pem 1024
 * openssl rsa -in rsa_1024_private.pem -out rsa_1024_public.pem -outform PEM -pubout
 * echo 'too many secrets' | openssl rsautl -encrypt -inkey rsa_1024_public.pem -pubin -out rsa_1024_encrypted.bin
 *
 * echo -n 'just testing' | openssl dgst -sha1 -binary > tosign.sha1
 * openssl pkeyutl -sign -in tosign.sha1 -inkey rsa_1024_private.pem -out rsa_1024_sig.bin -pkeyopt digest:sha1
 */

function createTestFunctions(keySize) {
  exports['testRsaDecryption' + keySize] = function(test) {
    var data = fs.readFileSync(__dirname +
      '/_files/rsa_' + keySize + '_encrypted.bin', 'binary');
    var keyPem = fs.readFileSync(__dirname +
      '/_files/rsa_' + keySize + '_private.pem', 'ascii');
    var key = forge.pki.privateKeyFromPem(keyPem);

    test.equal(key.decrypt(data), 'too many secrets\n');
    test.done();
  };

  exports['testRsaEncryption' + keySize] = function(test) {
    var message = "it need's to be about 20% cooler";

    /* first step, do public key encryption */
    var keyPem = fs.readFileSync(__dirname +
      '/_files/rsa_' + keySize + '_public.pem', 'ascii');
    var key = forge.pki.publicKeyFromPem(keyPem);

    var data = key.encrypt(message);

    /* second step, use private key decryption to verify successful encryption.
     * The encrypted message differs every time, since it is padded with random
     * data.  Therefore just rely on the decryption routine to work, which is
     * tested seperately against a externally provided encrypted message.
     */
    keyPem = fs.readFileSync(__dirname +
      '/_files/rsa_' + keySize + '_private.pem', 'ascii');
    key = forge.pki.privateKeyFromPem(keyPem);

    var res = key.decrypt(data);
    test.equal(res, message);
    test.done();
  };

  /**
   * Test RSA signature verification using various key sizes
   * and PKCS #1 v1.5 padding.
   */
  exports['testRsaVerify' + keySize] = function(test) {
    var sig = fs.readFileSync(__dirname +
      '/_files/rsa_' + keySize + '_sig.bin', 'binary');
    var keyPem = fs.readFileSync(__dirname +
      '/_files/rsa_' + keySize + '_public.pem', 'ascii');
    var key = forge.pki.publicKeyFromPem(keyPem);

    var md = forge.md.sha1.create();
    md.start();
    md.update('just testing');

    test.equal(key.verify(md.digest().getBytes(), sig), true);
    test.done();
  };

  /**
   * Test RSA signature generation with various key sizes and
   * PKCS #1 v1.5 padding.
   *
   * Those signatures are deterministic, therefore just generate
   * them and compare against pre-calculated ones.
   */
  exports['testRsaSign' + keySize] = function(test) {
    var keyPem = fs.readFileSync(__dirname +
      '/_files/rsa_' + keySize + '_private.pem', 'ascii');
    var key = forge.pki.privateKeyFromPem(keyPem);

    var md = forge.md.sha1.create();
    md.start();
    md.update('just testing');

    var exp = fs.readFileSync(__dirname +
      '/_files/rsa_' + keySize + '_sig.bin', 'binary');
    test.equal(key.sign(md), exp);

    test.done();
  };
}

var keySizes = [ 1024, 1025, 1031, 1032 ];
for(var i = 0; i < keySizes.length; i ++) {
  createTestFunctions(keySizes[i]);
}


/*
 * Test maximum message length detection in encryption routine.
 *
 * The message must be padded with at least eight bytes, two zero bytes and
 * one byte telling what the block type is.  This is 11 extra bytes are
 * added to the message.
 *
 * We're testing using a message of 118 bytes.  Together with the 11 extra
 * bytes the encryption block needs to be at least 129 bytes long.  This is
 * we need a key with a modulus length of at least 1025 bits.
 */
exports.testMessageLengthDetection_1024 = function(test) {
  var keyPem = fs.readFileSync(__dirname +
    '/_files/rsa_1024_public.pem', 'ascii');
  var key = forge.pki.publicKeyFromPem(keyPem);
  var message = new forge.util.ByteBuffer();
  message.fillWithByte(0, 118);

  test.throws(function() {
    key.encrypt(message.getBytes());
  });
  test.done();
};

exports.testMessageLengthDetection_1025 = function(test) {
  var keyPem = fs.readFileSync(__dirname +
    '/_files/rsa_1025_public.pem', 'ascii');
  var key = forge.pki.publicKeyFromPem(keyPem);
  var message = new forge.util.ByteBuffer();
  message.fillWithByte(0, 118);

  test.doesNotThrow(function() {
    key.encrypt(message.getBytes());
    test.done();
  });
};
