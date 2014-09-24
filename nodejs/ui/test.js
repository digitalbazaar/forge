var ASSERT = chai.assert;
mocha.setup({
  ui: 'bdd',
  timeout: 20000
});
requirejs.config({
  paths: {
    forge: 'forge',
    test: 'test'
  }
});
requirejs([
  'test/aes',
  'test/asn1',
  'test/csr',
  'test/des',
  'test/hmac',
  'test/kem',
  'test/md5',
  'test/mgf1',
  'test/pbkdf2',
  'test/pem',
  'test/pkcs1',
  'test/pkcs7',
  'test/pkcs12',
  'test/random',
  'test/rc2',
  'test/rsa',
  'test/sha1',
  'test/sha256',
  'test/sha512',
  'test/ssh',
  'test/tls',
  'test/util',
  'test/x509'
], function() {
  mocha.run();
});
