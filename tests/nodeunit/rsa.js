var forge = require('../../js/forge');
var fs = require('fs');

/* Key material in _files directory was created with OpenSSL using
 * these commands:
 *
 * openssl genrsa -out rsa_1024_private.pem 1024
 * openssl rsa -in rsa_1024_private.pem -out rsa_1024_public.pem -outform PEM -pubout
 * echo 'too many secrets' | openssl rsautl -encrypt -inkey rsa_1024_public.pem -pubin -out rsa_1024_encrypted.bin
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

}

var keySizes = [ 1024, 1025, 1031, 1032 ];
for(var i = 0; i < keySizes.length; i ++) {
  createTestFunctions(keySizes[i]);
}
