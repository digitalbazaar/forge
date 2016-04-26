if (typeof ASSERT === "undefined")
  var assert = require('assert');

define([
    '../test/util',
    '../test/md5',
    '../test/sha1',
    '../test/sha256',
    '../test/hmac',
    '../test/pbkdf2',
    '../test/mgf1',
    '../test/random',
    '../test/asn1',
    '../test/pem',
    '../test/rsa',
    '../test/kem',
    '../test/pkcs1',
    '../test/x509',
    '../test/csr',
    '../test/aes',
    '../test/rc2',
    '../test/des',
    '../test/pkcs7',
    '../test/pkcs12',
    '../test/tls'
], function() {
    mocha.run();
});
