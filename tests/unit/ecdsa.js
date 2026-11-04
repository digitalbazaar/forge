var ASSERT = require('assert');
var ECDSA = require('../../lib/ecdsa');
var SHA256 = require('../../lib/sha256');
var PKI = require('../../lib/pki');
var UTIL = require('../../lib/util');
var ASN1 = require('../../lib/asn1');

(function() {
  describe('ECDSA', function() {
    var testCurveNames = [
      'p192',
      'p224',
      'p256',
      'p384',
      'p521',
      'secp256k1',
    ]

    function test(curveName) {
      var kp;

      beforeEach(function() {
        // generate key pair from a seed
        var pwd = 'password';
        var md = SHA256.create();
        md.update(pwd, 'utf8');
        var seed = md.digest().getBytes();
        kp = ECDSA.generateKeyPair({name: curveName, seed: seed});
      });

      it(curveName + ': should sign and veriy', function() {
        var msg = 'hello'
        var signature = kp.privateKey.sign(msg);
        ASSERT.ok(kp.publicKey.verify(msg, signature));
        ASSERT.ok(!kp.publicKey.verify('wrong', signature));
      });

      it(curveName + ': should encode/decode privateKey to Der', function() {
        var encodedPrivateKey = eb64(kp.privateKey.toDer());
        var decodedPrivateKey = ECPrivateKey.fromAsn1(ASN1.fromDer(db64(encodedPrivateKey)));
        ASSERT.equal(encodedPrivateKey, eb64(decodedPrivateKey.toDer()));
      });

      it(curveName + ': should encode/decode publicKey to Der', function() {
        var encodedPublicKey = eb64(kp.publicKey.toDer());
        var decodedPublicKey = ECPublicKey.fromAsn1(ASN1.fromDer(db64(encodedPublicKey)));
        ASSERT.equal(encodedPublicKey, eb64(decodedPublicKey.toDer()));
      });

      it(curveName + ': should generate a random key pair', function() {
        var kp = ECDSA.generateKeyPair({name: curveName});
        ASSERT.ok(kp.privateKey);
        ASSERT.ok(kp.publicKey);
      });
    }

    for (var curveName of testCurveNames) {
      test(curveName);
    }

  });

  function eb64(buffer) {
    return UTIL.encode64(new UTIL.ByteBuffer(buffer).bytes());
  }

  function db64(x) {
    return new UTIL.ByteBuffer(UTIL.decode64(x), 'binary');
  }
})();
