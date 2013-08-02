(function() {

function Tests(ASSERT, PKI, RSA, MD, UTIL) {
  var _pem = {
    privateKey: '-----BEGIN RSA PRIVATE KEY-----\r\n' +
      'MIICXQIBAAKBgQDL0EugUiNGMWscLAVM0VoMdhDZEJOqdsUMpx9U0YZI7szokJqQ\r\n' +
      'NIwokiQ6EonNnWSMlIvy46AhnlRYn+ezeTeU7eMGTkP3VF29vXBo+dLq5e+8VyAy\r\n' +
      'Q3FzM1wI4ts4hRACF8w6mqygXQ7i/SDu8/rXqRGtvnM+z0MYDdKo80efzwIDAQAB\r\n' +
      'AoGAIzkGONi5G+JifmXlLJdplom486p3upf4Ce2/7mqfaG9MnkyPSairKD/JXvfh\r\n' +
      'NNWkkN8DKKDKBcVVElPgORYT0qwrWc7ueLBMUCbRXb1ZyfEulimG0R3kjUh7NYau\r\n' +
      'DaIkVgfykXGSQMZx8FoaT6L080zd+0emKDDYRrb+/kgJNJECQQDoUZoiC2K/DWNY\r\n' +
      'h3/ppZ0ane2y4SBmJUHJVMPQ2CEgxsrJTxet668ckNCKaOP/3VFPoWC41f17DvKq\r\n' +
      'noYINNntAkEA4JbZBZBVUrQFhHlrpXT4jzqtO2RlKZzEq8qmFZfEErxOT1WMyyCi\r\n' +
      'lAQ5gUKardo1Kf0omC8Xq/uO9ZYdED55KwJBALs6cJ65UFaq4oLJiQPzLd7yokuE\r\n' +
      'dcj8g71PLBTW6jPxIiMFNA89nz3FU9wIVp+xbMNhSoMMKqIPVPC+m0Rn260CQQDA\r\n' +
      'I83fWK/mZWUjBM33a68KumRiH238v8XyQxj7+C8i6D8G2GXvkigFAehAkb7LZZd+\r\n' +
      'KLuGFyPlWv3fVWHf99KpAkBQFKk3MRMl6IGJZUEFQe4l5whm8LkGU4acSqv9B3xt\r\n' +
      'qROkCrsFrMPqjuuzEmyHoQZ64r2PLJg7FOuyhBnQUOt4\r\n' +
      '-----END RSA PRIVATE KEY-----\r\n',
    publicKey: '-----BEGIN PUBLIC KEY-----\r\n' +
      'MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDL0EugUiNGMWscLAVM0VoMdhDZ\r\n' +
      'EJOqdsUMpx9U0YZI7szokJqQNIwokiQ6EonNnWSMlIvy46AhnlRYn+ezeTeU7eMG\r\n' +
      'TkP3VF29vXBo+dLq5e+8VyAyQ3FzM1wI4ts4hRACF8w6mqygXQ7i/SDu8/rXqRGt\r\n' +
      'vnM+z0MYDdKo80efzwIDAQAB\r\n' +
      '-----END PUBLIC KEY-----\r\n'
  };
  var _signature =
    '9200ece65cdaed36bcc20b94c65af852e4f88f0b4fe5b249d54665f815992ac4' +
    '3a1399e65d938c6a7f16dd39d971a53ca66523209dbbfbcb67afa579dbb0c220' +
    '672813d9e6f4818f29b9becbb29da2032c5e422da97e0c39bfb7a2e7d568615a' +
    '5073af0337ff215a8e1b2332d668691f4fb731440055420c24ac451dd3c913f4';

  describe('rsa', function() {
    it('should generate 512 bit key pair', function() {
      var pair = RSA.generateKeyPair(512);
      ASSERT.equal(PKI.privateKeyToPem(pair.privateKey).indexOf('-----BEGIN RSA PRIVATE KEY-----'), 0);
      ASSERT.equal(PKI.publicKeyToPem(pair.publicKey).indexOf('-----BEGIN PUBLIC KEY-----'), 0);

      // sign and verify
      var md = MD.sha1.create();
      md.update('0123456789abcdef');
      var signature = pair.privateKey.sign(md);
      ASSERT.ok(pair.publicKey.verify(md.digest().getBytes(), signature));
    });

    it('should convert private key to/from PEM', function() {
      var privateKey = PKI.privateKeyFromPem(_pem.privateKey);
      ASSERT.equal(PKI.privateKeyToPem(privateKey), _pem.privateKey);
    });

    it('should convert public key to/from PEM', function() {
      var publicKey = PKI.publicKeyFromPem(_pem.publicKey);
      ASSERT.equal(PKI.publicKeyToPem(publicKey), _pem.publicKey);
    });

    (function() {
      var algorithms = ['aes128', 'aes192', 'aes256', '3des'];
      for(var i = 0; i < algorithms.length; ++i) {
        var algorithm = algorithms[i];
        it('should PKCS#8 encrypt and decrypt private key with ' + algorithm, function() {
          var privateKey = PKI.privateKeyFromPem(_pem.privateKey);
          var encryptedPem = PKI.encryptRsaPrivateKey(
             privateKey, 'password', {algorithm: algorithm});
          var privateKey = PKI.decryptRsaPrivateKey(encryptedPem, 'password');
          ASSERT.equal(PKI.privateKeyToPem(privateKey), _pem.privateKey);
        });
      }
    })();

    it('should verify signature', function() {
      var publicKey = PKI.publicKeyFromPem(_pem.publicKey);
      var md = MD.sha1.create();
      md.update('0123456789abcdef');
      var signature = UTIL.hexToBytes(_signature);
      ASSERT.ok(publicKey.verify(md.digest().getBytes(), signature));
    });

    it('should sign and verify', function() {
      var privateKey = PKI.privateKeyFromPem(_pem.privateKey);
      var publicKey = PKI.publicKeyFromPem(_pem.publicKey);
      var md = MD.sha1.create();
      md.update('0123456789abcdef');
      var signature = privateKey.sign(md);
      ASSERT.ok(publicKey.verify(md.digest().getBytes(), signature));
    });
  });
}

// check for AMD
if(typeof define === 'function') {
  define([
    'forge/pki',
    'forge/rsa',
    'forge/md',
    'forge/util'
  ], function(PKI, RSA, MD, UTIL) {
    Tests(
      // Global provided by test harness
      ASSERT,
      PKI(),
      RSA(),
      MD(),
      UTIL()
    );
  });
}
// assume NodeJS
else if(typeof module === 'object' && module.exports) {
  Tests(
    require('assert'),
    require('../../js/pki')(),
    require('../../js/rsa')(),
    require('../../js/md')(),
    require('../../js/util')());
}

})();
