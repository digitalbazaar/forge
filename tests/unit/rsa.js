var ASSERT = require('assert');
var FORGE = require('../../lib/forge');
var JSBN = require('../../lib/jsbn');
var MD = require('../../lib/md.all');
var MGF = require('../../lib/mgf');
var PKI = require('../../lib/pki');
var PSS = require('../../lib/pss');
var RANDOM = require('../../lib/random');
var RSA = require('../../lib/rsa');
var UTIL = require('../../lib/util');

(function() {
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
    privateKeyInfo: '-----BEGIN PRIVATE KEY-----\r\n' +
      'MIICdwIBADANBgkqhkiG9w0BAQEFAASCAmEwggJdAgEAAoGBAMvQS6BSI0Yxaxws\r\n' +
      'BUzRWgx2ENkQk6p2xQynH1TRhkjuzOiQmpA0jCiSJDoSic2dZIyUi/LjoCGeVFif\r\n' +
      '57N5N5Tt4wZOQ/dUXb29cGj50url77xXIDJDcXMzXAji2ziFEAIXzDqarKBdDuL9\r\n' +
      'IO7z+tepEa2+cz7PQxgN0qjzR5/PAgMBAAECgYAjOQY42Lkb4mJ+ZeUsl2mWibjz\r\n' +
      'qne6l/gJ7b/uap9ob0yeTI9JqKsoP8le9+E01aSQ3wMooMoFxVUSU+A5FhPSrCtZ\r\n' +
      'zu54sExQJtFdvVnJ8S6WKYbRHeSNSHs1hq4NoiRWB/KRcZJAxnHwWhpPovTzTN37\r\n' +
      'R6YoMNhGtv7+SAk0kQJBAOhRmiILYr8NY1iHf+mlnRqd7bLhIGYlQclUw9DYISDG\r\n' +
      'yslPF63rrxyQ0Ipo4//dUU+hYLjV/XsO8qqehgg02e0CQQDgltkFkFVStAWEeWul\r\n' +
      'dPiPOq07ZGUpnMSryqYVl8QSvE5PVYzLIKKUBDmBQpqt2jUp/SiYLxer+471lh0Q\r\n' +
      'PnkrAkEAuzpwnrlQVqrigsmJA/Mt3vKiS4R1yPyDvU8sFNbqM/EiIwU0Dz2fPcVT\r\n' +
      '3AhWn7Fsw2FKgwwqog9U8L6bRGfbrQJBAMAjzd9Yr+ZlZSMEzfdrrwq6ZGIfbfy/\r\n' +
      'xfJDGPv4LyLoPwbYZe+SKAUB6ECRvstll34ou4YXI+Va/d9VYd/30qkCQFAUqTcx\r\n' +
      'EyXogYllQQVB7iXnCGbwuQZThpxKq/0HfG2pE6QKuwWsw+qO67MSbIehBnrivY8s\r\n' +
      'mDsU67KEGdBQ63g=\r\n' +
      '-----END PRIVATE KEY-----\r\n',
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
    // check a pair
    function _pairCheck(pair) {
      // PEM check
      ASSERT.equal(PKI.privateKeyToPem(pair.privateKey).indexOf('-----BEGIN RSA PRIVATE KEY-----'), 0);
      ASSERT.equal(PKI.publicKeyToPem(pair.publicKey).indexOf('-----BEGIN PUBLIC KEY-----'), 0);

      // sign and verify
      var md = MD.sha1.create();
      md.update('0123456789abcdef');
      var signature = pair.privateKey.sign(md);
      ASSERT.ok(pair.publicKey.verify(md.digest().getBytes(), signature));
    }

    // compare pairs
    function _pairCmp(pair1, pair2) {
      var pem1 = {
        privateKey: PKI.privateKeyToPem(pair1.privateKey),
        publicKey: PKI.publicKeyToPem(pair1.publicKey)
      };
      var pem2 = {
        privateKey: PKI.privateKeyToPem(pair2.privateKey),
        publicKey: PKI.publicKeyToPem(pair2.publicKey)
      };
      ASSERT.equal(pem1.privateKey, pem2.privateKey);
      ASSERT.equal(pem1.publicKey, pem2.publicKey);
    }

    // create same prng
    function _samePrng() {
      var prng = RANDOM.createInstance();
      prng.seedFileSync = function(needed) {
        return UTIL.fillString('a', needed);
      };
      return prng;
    }

    // generate pair in sync mode
    function _genSync(options) {
      options = options || {samePrng: false};
      var pair;
      if(options.samePrng) {
        pair = RSA.generateKeyPair(512, {prng: _samePrng()});
      } else {
        pair = RSA.generateKeyPair(512);
      }
      _pairCheck(pair);
      return pair;
    }

    // generate pair in async mode
    function _genAsync(options, callback) {
      if(typeof callback !== 'function') {
        callback = options;
        options = {samePrng: false};
      }
      var genOptions = {
        bits: 512,
        workerScript: '/forge/prime.worker.js'
      };
      if(options.samePrng) {
        genOptions.prng = _samePrng();
      }
      if('workers' in options) {
        genOptions.workers = options.workers;
      }
      RSA.generateKeyPair(genOptions, function(err, pair) {
        ASSERT.ifError(err);
        _pairCheck(pair);
        callback(pair);
      });
    }

    // check if keygen params use deterministic algorithm
    // NOTE: needs to match implementation details
    function isDeterministic(isPrng, isAsync, isPurejs) {
      // always needs to have a prng
      if(!isPrng) {
        return false;
      }
      if(UTIL.isNodejs) {
        // Node versions >= 10.12.0 support native keyPair generation,
        // which is non-deterministic
        if(isAsync && !isPurejs &&
          typeof require('crypto').generateKeyPair === 'function') {
          return false;
        }
        if(!isAsync && !isPurejs &&
          typeof require('crypto').generateKeyPairSync === 'function') {
          return false;
        }
      } else {
        // async browser code has race conditions with multiple workers
        if(isAsync) {
          return false;
        }
      }
      // will run deterministic algorithm
      return true;
    }

    it('should generate 512 bit key pair (sync)', function() {
      _genSync();
    });

    it('should generate 512 bit key pair (sync+purejs)', function() {
      // save
      var purejs = FORGE.options.usePureJavaScript;
      // test pure mode
      FORGE.options.usePureJavaScript = true;
      _genSync();
      // restore
      FORGE.options.usePureJavaScript = purejs;
    });

    it('should generate 512 bit key pair (async)', function(done) {
      _genAsync(function() {
        done();
      });
    });

    it('should generate 512 bit key pair (async+purejs)', function(done) {
      // save
      var purejs = FORGE.options.usePureJavaScript;
      // test pure mode
      FORGE.options.usePureJavaScript = true;
      _genAsync(function() {
        // restore
        FORGE.options.usePureJavaScript = purejs;
        done();
      });
    });

    it('should generate 512 bit key pair (async+workers)', function(done) {
      _genAsync({
        workers: -1
      }, function() {
        done();
      });
    });

    it('should generate same 512 bit key pair (prng+sync,prng+sync)',
      function() {
      var pair1 = _genSync({samePrng: true});
      var pair2 = _genSync({samePrng: true});
      _pairCmp(pair1, pair2);
    });

    it('should generate same 512 bit key pair (prng+sync,prng+sync+purejs)',
      function() {
      if(!isDeterministic(true, false, false) ||
        !isDeterministic(true, false, true)) {
        this.skip();
      }
      var pair1 = _genSync({samePrng: true});
      // save
      var purejs = FORGE.options.usePureJavaScript;
      // test pure mode
      FORGE.options.usePureJavaScript = true;
      var pair2 = _genSync({samePrng: true});
      // restore
      FORGE.options.usePureJavaScript = purejs;
      _pairCmp(pair1, pair2);
    });

    it('should generate same 512 bit key pair ' +
      '(prng+sync+purejs,prng+sync+purejs)', function() {
      if(!isDeterministic(true, false, true) ||
        !isDeterministic(true, false, true)) {
        this.skip();
      }
      // save
      var purejs = FORGE.options.usePureJavaScript;
      // test pure mode
      FORGE.options.usePureJavaScript = true;
      var pair1 = _genSync({samePrng: true});
      var pair2 = _genSync({samePrng: true});
      // restore
      FORGE.options.usePureJavaScript = purejs;
      _pairCmp(pair1, pair2);
    });

    it('should generate same 512 bit key pair (prng+sync,prng+async)',
      function(done) {
      if(!isDeterministic(true, false, false) ||
        !isDeterministic(true, true, false)) {
        this.skip();
      }
      var pair1 = _genSync({samePrng: true});
      _genAsync({samePrng: true}, function(pair2) {
        _pairCmp(pair1, pair2);
        done();
      });
    });

    it('should generate same 512 bit key pair (prng+async,prng+sync)',
      function(done) {
      if(!isDeterministic(true, true, false) ||
        !isDeterministic(true, false, false)) {
        this.skip();
      }
      _genAsync({samePrng: true}, function(pair1) {
        var pair2 = _genSync({samePrng: true});
        _pairCmp(pair1, pair2);
        done();
      });
    });

    it('should generate same 512 bit key pair (prng+async,prng+async)',
      function(done) {
      if(!isDeterministic(true, true, false) ||
        !isDeterministic(true, true, false)) {
        this.skip();
      }
      var pair1;
      var pair2;
      // finish when both complete
      function _done() {
        if(pair1 && pair2) {
          _pairCmp(pair1, pair2);
          done();
        }
      }
      _genAsync({samePrng: true}, function(pair) {
        pair1 = pair;
        _done();
      });
      _genAsync({samePrng: true}, function(pair) {
        pair2 = pair;
        _done();
      });
    });

    it('should convert private key to/from PEM', function() {
      var privateKey = PKI.privateKeyFromPem(_pem.privateKey);
      ASSERT.equal(PKI.privateKeyToPem(privateKey), _pem.privateKey);
    });

    it('should convert public key to/from PEM', function() {
      var publicKey = PKI.publicKeyFromPem(_pem.publicKey);
      ASSERT.equal(PKI.publicKeyToPem(publicKey), _pem.publicKey);
    });

    it('should convert a PKCS#8 PrivateKeyInfo to/from PEM', function() {
      var privateKey = PKI.privateKeyFromPem(_pem.privateKeyInfo);
      var rsaPrivateKey = PKI.privateKeyToAsn1(privateKey);
      var pki = PKI.wrapRsaPrivateKey(rsaPrivateKey);
      ASSERT.equal(PKI.privateKeyInfoToPem(pki), _pem.privateKeyInfo);
    });

    (function() {
      var algorithms = ['aes128', 'aes192', 'aes256', '3des', 'des'];
      algorithms.forEach(function(algorithm) {
        it('should PKCS#8 encrypt and decrypt private key with ' + algorithm, function() {
          var privateKey = PKI.privateKeyFromPem(_pem.privateKey);
          var encryptedPem = PKI.encryptRsaPrivateKey(
            privateKey, 'password', {algorithm: algorithm});
          privateKey = PKI.decryptRsaPrivateKey(encryptedPem, 'password');
          ASSERT.equal(PKI.privateKeyToPem(privateKey), _pem.privateKey);
        });
      });
    })();

    (function() {
      var algorithms = ['aes128', 'aes192', 'aes256'];
      var prfAlgorithms = ['sha1', 'sha224', 'sha256', 'sha384', 'sha512'];
      algorithms.forEach(function(algorithm) {
        prfAlgorithms.forEach(function(prfAlgorithm) {
          it('should PKCS#8 encrypt and decrypt private key with ' + algorithm +
            ' encryption and ' + prfAlgorithm + ' PRF', function() {
            var privateKey = PKI.privateKeyFromPem(_pem.privateKey);
            var encryptedPem = PKI.encryptRsaPrivateKey(
              privateKey, 'password', {
                algorithm: algorithm,
                prfAlgorithm: prfAlgorithm
              });
            privateKey = PKI.decryptRsaPrivateKey(encryptedPem, 'password');
            ASSERT.equal(PKI.privateKeyToPem(privateKey), _pem.privateKey);
          });
        });
      });
    })();

    (function() {
      var algorithms = ['aes128', 'aes192', 'aes256', '3des', 'des'];
      algorithms.forEach(function(algorithm) {
        it('should legacy (OpenSSL style) encrypt and decrypt private key with ' + algorithm, function() {
          var privateKey = PKI.privateKeyFromPem(_pem.privateKey);
          var encryptedPem = PKI.encryptRsaPrivateKey(
             privateKey, 'password', {algorithm: algorithm, legacy: true});
          privateKey = PKI.decryptRsaPrivateKey(encryptedPem, 'password');
          ASSERT.equal(PKI.privateKeyToPem(privateKey), _pem.privateKey);
        });
      });
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

    it('should generate missing CRT parameters, sign, and verify', function() {
      var privateKey = PKI.privateKeyFromPem(_pem.privateKey);

      // remove dQ, dP, and qInv
      privateKey = RSA.setPrivateKey(
        privateKey.n, privateKey.e, privateKey.d,
        privateKey.p, privateKey.q);

      var publicKey = PKI.publicKeyFromPem(_pem.publicKey);
      var md = MD.sha1.create();
      md.update('0123456789abcdef');
      var signature = privateKey.sign(md);
      ASSERT.ok(publicKey.verify(md.digest().getBytes(), signature));
    });

    it('should sign and verify with a private key containing only e, n, and d parameters', function() {
      var privateKey = PKI.privateKeyFromPem(_pem.privateKey);

      // remove all CRT parameters from private key, so that it consists
      // only of e, n and d (which make a perfectly valid private key, but its
      // operations are slower)
      privateKey = RSA.setPrivateKey(
        privateKey.n, privateKey.e, privateKey.d);

      var publicKey = PKI.publicKeyFromPem(_pem.publicKey);
      var md = MD.sha1.create();
      md.update('0123456789abcdef');
      var signature = privateKey.sign(md);
      ASSERT.ok(publicKey.verify(md.digest().getBytes(), signature));
    });

    (function() {
      var tests = [{
        keySize: 1024,
        privateKeyPem: '-----BEGIN RSA PRIVATE KEY-----\r\n' +
          'MIICWwIBAAKBgQDCjvkkLWNTeYXqEsqGiVCW/pDt3/qAodNMHcU9gOU2rxeWwiRu\r\n' +
          'OhhLqmMxXHLi0oP5Xmg0m7zdOiLMEyzzyRzdp21aqp3k5qtuSDkZcf1prsp1jpYm\r\n' +
          '6z9EGpaSHb64BCuUsQGmUPKutd5RERKHGZXtiRuvvIyue7ETq6VjXrOUHQIDAQAB\r\n' +
          'AoGAOKeBjTNaVRhyEnNeXkbmHNIMSfiK7aIx8VxJ71r1ZDMgX1oxWZe5M29uaxVM\r\n' +
          'rxg2Lgt7tLYVDSa8s0hyMptBuBdy3TJUWruDx85uwCrWnMerCt/iKVBS22fv5vm0\r\n' +
          'LEq/4gjgIVTZwgqbVxGsBlKcY2VzxAfYqYzU8EOZBeNhZdECQQDy+PJAPcUN2xOs\r\n' +
          '6qy66S91x6y3vMjs900OeX4+bgT4VSVKmLpqRTPizzcL07tT4+Y+pAAOX6VstZvZ\r\n' +
          '6iFDL5rPAkEAzP1+gaRczboKoJWKJt0uEMUmztcY9NXJFDmjVLqzKwKjcAoGgIal\r\n' +
          'h+uBFT9VJ16QajC7KxTRLlarzmMvspItUwJAeUMNhEpPwm6ID1DADDi82wdgiALM\r\n' +
          'NJfn+UVhYD8Ac//qsKQwxUDseFH6owh1AZVIIBMxg/rwUKUCt2tGVoW3uQJAIt6M\r\n' +
          'Aml/D8+xtxc45NuC1n9y1oRoTl1/Ut1rFyKbD5nnS0upR3uf9LruvjqDtaq0Thvz\r\n' +
          '+qQT4RoFJ5pfprSO2QJAdMkfNWRqECfAhZyQuUrapeWU3eQ0wjvktIynCIwiBDd2\r\n' +
          'MfjmVXzBJhMk6dtINt+vBEITVQEOdtyTgDt0y3n2Lw==\r\n' +
          '-----END RSA PRIVATE KEY-----\r\n',
        publicKeyPem: '-----BEGIN PUBLIC KEY-----\r\n' +
          'MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDCjvkkLWNTeYXqEsqGiVCW/pDt\r\n' +
          '3/qAodNMHcU9gOU2rxeWwiRuOhhLqmMxXHLi0oP5Xmg0m7zdOiLMEyzzyRzdp21a\r\n' +
          'qp3k5qtuSDkZcf1prsp1jpYm6z9EGpaSHb64BCuUsQGmUPKutd5RERKHGZXtiRuv\r\n' +
          'vIyue7ETq6VjXrOUHQIDAQAB\r\n' +
          '-----END PUBLIC KEY-----\r\n',
        encrypted: 'jsej3OoacmJ1VjWrlw68F+drnQORAuKAqVu6RMbz1xSXjzA355vctrJZXolRU0mvzuu/6VuNynkKGGyRJ6DHt85CvwTMChw4tOMV4Dy6bgnUt3j+DZA2sWTwFhOlpzvNQMK70QpuqrXtOZmAO59EwoDeJkW/iH6t4YzNOVYo9Jg=',
        signature: 'GT0/3EV2zrXxPd1ydijJq3R7lkI4c0GtcprgpG04dSECv/xyXtikuzivxv7XzUdHpu6QiYmM0xE4D4i7LK3Mzy+f7aB4o/dg8XXO3htLiBzVI+ZJCRh06RdYctPtclAWmyZikZ8Etw3NnA/ldKuG4jApbwRb21UFm5gYLrJ4SP4=',
        signaturePss: 'F4xffaANDBjhFxeSJx8ANuBbdhaWZjUHRQh4ueYQMPPCaR2mpwdqxE04sbgNgIiZzBuLIAI4HpTMMoDk3Rruhjefx3+9UhzTxgB0hRI+KzRChRs+ToltWWDZdYzt9T8hfTlELeqT4V8HgjDuteO/IAvIVlRIBwMNv53Iebu1FY4=',
        signatureWithAbcSalt: 'GYA/Zp8G+jqG2Fu7Um+XP7Cr/yaVdzJN8lyt57Lw6gFflia2CPbOVMLyqLzD7fKoE8UD0Rc6DF8k04xhEu60sudw2nxGHeDvpL4M9du0uYra/WSr9kv7xNjAW62NyNerDngHD2J7O8gQ07TZiTXkrfS724vQab5xZL/+FhvisMY=',
        signatureWithCustomPrng: 'LzWcUpUYK+URDp72hJbz1GVEp0rG0LHjd+Pdh2w5rfQFbUThbmXDl3X6DUT5UZr5RjUSHtc2usvH+w49XskyIJJO929sUk9EkMJMK/6QAnYYEp5BA+48pdGNNMZyjIbhyl9Y4lInzFPX8XYMM8o+tdSK+hj+dW5OPdnwWbDtR7U='
      }, {
        keySize: 1025,
        privateKeyPem: '-----BEGIN RSA PRIVATE KEY-----\r\n' +
          'MIICXgIBAAKBgQGIkej4PDlAigUh5fbbHp1WXuTHhOdQfAke+LoH0TM4uzn0QmgK\r\n' +
          'SJqxzB1COJ5o0DwZw/NR+CNy7NUrly+vmh2YPwsaqN+AsYBF9qsF93oN8/TBtaL/\r\n' +
          'GRoRGpDcCglkj1kZnDaWR79NsG8mC0TrvQCkcCLOP0c2Ux1hRbntOetGXwIDAQAB\r\n' +
          'AoGBAIaJWsoX+ZcAthmT8jHOICXFh6pJBe0zVPzkSPz82Q0MPSRUzcsYbsuYJD7Z\r\n' +
          'oJBTLQW3feANpjhwqe2ydok7y//ONm3Th53Bcu8jLfoatg4KYxNFIwXEO10mPOld\r\n' +
          'VuDIGrBkTABe6q2P5PeUKGCKLT6i/u/2OTXTrQiJbQ0gU8thAkEBjqcFivWMXo34\r\n' +
          'Cb9/EgfWCCtv9edRMexgvcFMysRsbHJHDK9JjRLobZltwtAv3cY7F3a/Cu1afg+g\r\n' +
          'jAzm5E3gowJBAPwYFHTLzaZToxFKNQztWrPsXF6YfqHpPUUIpT4UzL6DhGG0M00U\r\n' +
          'qMyhkYRRqmGOSrSovjg2hjM2643MUUWxUxUCQDPkk/khu5L3YglKzyy2rmrD1MAq\r\n' +
          'y0v3XCR3TBq89Ows+AizrJxbkLvrk/kfBowU6M5GG9o9SWFNgXWZnFittocCQQDT\r\n' +
          'e1P1419DUFi1UX6NuLTlybx3sxBQvf0jY6xUF1jn3ib5XBXJbTJqcIRF78iyjI9J\r\n' +
          'XWIugDc20bTsQOJRSAA9AkEBU8kpueHBaiXTikqqlK9wvc2Lp476hgyKVmVyBGye\r\n' +
          '9TLTWkTCzDPtManLy47YtXkXnmyazS+DlKFU61XAGEnZfg==\r\n' +
          '-----END RSA PRIVATE KEY-----\r\n',
        publicKeyPem: '-----BEGIN PUBLIC KEY-----\r\n' +
          'MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQGIkej4PDlAigUh5fbbHp1WXuTH\r\n' +
          'hOdQfAke+LoH0TM4uzn0QmgKSJqxzB1COJ5o0DwZw/NR+CNy7NUrly+vmh2YPwsa\r\n' +
          'qN+AsYBF9qsF93oN8/TBtaL/GRoRGpDcCglkj1kZnDaWR79NsG8mC0TrvQCkcCLO\r\n' +
          'P0c2Ux1hRbntOetGXwIDAQAB\r\n' +
          '-----END PUBLIC KEY-----\r\n',
        encrypted: 'AOVeCUN8BOVkZvt4mxyNn/yCYE1MZ40A3e/osh6EvCBcJ09hyYbx7bzKSrdkhRnDyW0pGtgP352CollasllQZ9HlfI2Wy9zKM0aYZZn8OHBA+60Tc3xHHDGznLZqggUKuhoNpj+faVZ1uzb285eTpQQa+4mLUue2svJD4ViM8+ng',
        signature: 'AFSx0axDYXlF2rO3ofgUhYSI8ZlIWtJUUZ62PhgdBp9O5zFqMX3DXoiov1e7NenSOz1khvTSMctFWzKP3GU3F0yewe+Yd3UAZE0dM8vAxigSSfAchUkBDmp9OFuszUie63zwWwpG+gXtvyfueZs1RniBvW1ZmXJvS+HFgX4ouzwd',
        signaturePss: 'AQvBdhAXDpu+7RpcybMgwuTUk6w+qa08Lcq3G1xHY4kC7ZUzauZd/Jn9e0ePKApDqs7eDNAOV+dQkU2wiH/uBg6VGelzb0hFwcpSLyBW92Vw0q3GlzY7myWn8qnNzasrt110zFflWQa1GiuzH/C8f+Z82/MzlWDxloJIYbq2PRC8',
        signatureWithAbcSalt: 'AW4bKnG/0TGvAZgqX5Dk+fXpUNgX7INFelE46d3m+spaMTG5XalY0xP1sxWfaE/+Zl3FmZcfTNtfOCo0eNRO1h1+GZZfp32ZQZmZvkdUG+dUQp318LNzgygrVf/5iIX+QKV5/soSDuAHBzS7yDfMgzJfnXNpFE/zPLOgZIoOIuLq',
        signatureWithCustomPrng: 'AVxfCyGC/7Y3kz//eYFEuWQijjR7eR05AM36CwDlLsVkDRtXoeVzz2yTFBdP+i+QgQ73C/I3lLtvXTwfleorvIX9YncVBeGDQXssmULxzqsM3izaLfJXCRAGx9ErL1Az10+fAqPZpq954OVSDqrR/61Q7CsMY7CiQO3nfIIaxgVL'
      }, {
        keySize: 1031,
        privateKeyPem: '-----BEGIN RSA PRIVATE KEY-----\r\n' +
          'MIICXwIBAAKBgWyeKqA2oA4klYrKT9hjjutYQksJNN0cxwaQwIm9AYiLxOsYtT/C\r\n' +
          'ovJx5Oy1EvkbYQbfvYsGISUx9bW8yasZkTHR55IbW3+UptvQjTDtdxBQTgQOpsAh\r\n' +
          'BJtZYY3OmyH9Sj3F3oB//oyriNoj0QYyfsvlO8UsMmLzpnf6qfZBDHA/9QIDAQAB\r\n' +
          'AoGBBj/3ne5muUmbnTfU7lOUNrCGaADonMx6G0ObAJHyk6PPOePbEgcmDyNEk+Y7\r\n' +
          'aEAODjIzmttIbvZ39/Qb+o9nDmCSZC9VxiYPP+rjOzPglCDT5ks2Xcjwzd3If6Ya\r\n' +
          'Uw6P31Y760OCYeTb4Ib+8zz5q51CkjkdX5Hq/Yu+lZn0Vx7BAkENo83VfL+bwxTm\r\n' +
          'V7vR6gXqTD5IuuIGHL3uTmMNNURAP6FQDHu//duipys83iMChcOeXtboE16qYrO0\r\n' +
          '9KC0cqL4JQJBB/aYo/auVUGZA6f50YBp0b2slGMk9TBQG0iQefuuSyH4kzKnt2e3\r\n' +
          'Q40SBmprcM+DfttWJ11bouec++goXjz+95ECQQyiTWYRxulgKVuyqCYnvpLnTEnR\r\n' +
          '0MoYlVTHBriVPkLErYaYCYgse+SNM1+N4p/Thv6KmkUcq/Lmuc5DSRfbl1iBAkEE\r\n' +
          '7GKtJQvd7EO1bfpXnARQx+tWhwHHkgpFBBVHReMZ0rQEFhJ5o2c8HZEiZFNvGO2c\r\n' +
          '1fErP14zlu2JFZ03vpCI8QJBCQz9HL28VNjafSAF2mon/SNjKablRjoGGKSoSdyA\r\n' +
          'DHDZ/LeRsTp2dg8+bSiG1R+vPqw0f/BT+ux295Sy9ocGEM8=\r\n' +
          '-----END RSA PRIVATE KEY-----\r\n',
        publicKeyPem: '-----BEGIN PUBLIC KEY-----\r\n' +
          'MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgWyeKqA2oA4klYrKT9hjjutYQksJ\r\n' +
          'NN0cxwaQwIm9AYiLxOsYtT/CovJx5Oy1EvkbYQbfvYsGISUx9bW8yasZkTHR55Ib\r\n' +
          'W3+UptvQjTDtdxBQTgQOpsAhBJtZYY3OmyH9Sj3F3oB//oyriNoj0QYyfsvlO8Us\r\n' +
          'MmLzpnf6qfZBDHA/9QIDAQAB\r\n' +
          '-----END PUBLIC KEY-----\r\n',
        encrypted: 'ShSS4/fEAkuS6XiQakhOpWp82IXaaCaDNtsndU4uokvriqgCGZyqc+IkIk3eVmZ8bn4vVIRR43ydFuvGgsptVjizOdLGZudph3TJ1clcYEMcCXk4z5HaEu0bx5SW9jmzHhE/z+WV8PB48q7y7C2qtmPmfttG2NMsNLBvkiaDopRO',
        signature: 'Z3vYgRdezrWmdA3NC1Uz2CcHRTcE+/C2idGZA1FjUGqFztAHQ31k0QW/F5zuJdKvg8LQU45S3KxW+OQpbGPL98QbzJLhml88mFGe6OinLXJbi7UQWrtXwamc2jMdiXwovSLbXaXy6PX2QW089iC8XuAZftVi3T/IKV0458FQQprg',
        signaturePss: 'R6QsK6b3QinIPZPamm/dP0Zndqti1TzAkFTRSZJaRSa1u2zuvZC5QHF4flDjEtHosWeDyxrBE7PHGQZ0b1bHv9qgHGsJCMwaQPj3AWj9fjYmx7b86KM2vHr8q/vqDaa9pTvVRSSwvD6fwoZPc9twQEfdjdDBAiy23yLDzk/zZiwM',
        signatureWithAbcSalt: 'Ep9qx4/FPNcWTixWhvL2IAyJR69o5I4MIJi3cMAhDmpuTvAaL/ThQwFWkBPPOPT4Jbumnu6ELjPNjo72wa00e5k64qnZgy1pauBPMlXRlKehRc9UJZ6+xot642z8Qs+rt89OgbYTsvlyr8lzXooUHz/lPpfawYCqd7maRMs8YlYM',
        signatureWithCustomPrng: 'NHAwyn2MdM5ez/WbDNbu2A2JNS+cRiWk/zBoh0lg3aq/RsBS0nrYr4AGiC5jt6KWVcN4AIVOomYtX2k+MhLoemN2t2rDj/+LXOeU7kgCAz0q0ED2NFQz7919JU+PuYXMy03qTMfl5jbvStdi/00eQHjJKGEH+xAgrDcED2lrhtCu'
      }, {
        keySize: 1032,
        privateKeyPem: '-----BEGIN RSA PRIVATE KEY-----\r\n' +
          'MIICYQIBAAKBggDPhzn5I3GecxWt5DKbP+VhM2AFNSOL0+VbYEOR1hnlZdLbxGK4\r\n' +
          'cPQzMr2qT6dyttJcsgWr3xKobPkz7vsTZzQATSiekm5Js5dGpaj5lrq/x2+WTZvn\r\n' +
          '55x9M5Y5dlpusDMKcC3KaIX/axc+MbvPFzo6Eli7JLCWdBg01eKo30knil0CAwEA\r\n' +
          'AQKBggCNl/sjFF7SOD1jbt5kdL0hi7cI9o+xOLs1lEGmAEmc7dNnZN/ibhb/06/6\r\n' +
          'wuxB5aEz47bg5IvLZMbG+1hNjc26D0J6Y3Ltwrg8f4ZMdDrh4v0DZ8hy/HbEpMrJ\r\n' +
          'Td5dk3mtw9FLow10MB5udPLTDKhfDpTcWiObKm2STtFeBk3xeEECQQ6Cx6bZxQJ1\r\n' +
          'zCxflV5Xi8BgAQaUKMqygugte+HpOLflL0j1fuZ0rPosUyDOEFkTzOsPxBYYOU8i\r\n' +
          'Gzan1GvW3WwRAkEOTTRt849wpgC9xx2pF0IrYEVmv5gEMy3IiRfCNgEoBwpTWVf4\r\n' +
          'QFpN3V/9GFz0WQEEYo6OTmkNcC3Of5zbHhu1jQJBBGxXAYQ2KnbP4uLL/DMBdYWO\r\n' +
          'Knw1JvxdLPrYXVejI2MoE7xJj2QXajbirAhEMXL4rtpicj22EmoaE4H7HVgkrJEC\r\n' +
          'QQq2V5w4AGwvW4TLHXNnYX/eB33z6ujScOuxjGNDUlBqHZja5iKkCUAjnl+UnSPF\r\n' +
          'exaOwBrlrpiLOzRer94MylKNAkEBmI58bqfkI5OCGDArAsJ0Ih58V0l1UW35C1SX\r\n' +
          '4yDoXSM5A/xQu2BJbXO4jPe3PnDvCVCEyKpbCK6bWbe26Y7zuw==\r\n' +
          '-----END RSA PRIVATE KEY-----\r\n',
        publicKeyPem: '-----BEGIN PUBLIC KEY-----\r\n' +
          'MIGgMA0GCSqGSIb3DQEBAQUAA4GOADCBigKBggDPhzn5I3GecxWt5DKbP+VhM2AF\r\n' +
          'NSOL0+VbYEOR1hnlZdLbxGK4cPQzMr2qT6dyttJcsgWr3xKobPkz7vsTZzQATSie\r\n' +
          'km5Js5dGpaj5lrq/x2+WTZvn55x9M5Y5dlpusDMKcC3KaIX/axc+MbvPFzo6Eli7\r\n' +
          'JLCWdBg01eKo30knil0CAwEAAQ==\r\n' +
          '-----END PUBLIC KEY-----\r\n',
        encrypted: 'pKTbv+xgXPDc+wbjsANFu1/WTcmy4aZFKXKnxddHbU5S0Dpdj2OqCACiBwu1oENPMgPAJ27XRbFtKG+eS8tX47mKP2Fo0Bi+BPFtzuQ1bj3zUzTwzjemT+PU+a4Tho/eKjPhm6xrwGAoQH2VEDEpvcYf+SRmGFJpJ/zPUrSxgffj',
        signature: 'R9WBFprCfcIC4zY9SmBpEM0E+cr5j4gMn3Ido5mktoR9VBoJqC6eR6lubIPvZZUz9e4yUSYX0squ56Q9Y0yZFQjTHgsrlmhB2YW8kpv4h8P32Oz2TLcMJK9R2tIh9vvyxwBkd/Ml1qG60GnOFUFzxUad9VIlzaF1PFR6EfnkgBUW',
        signaturePss: 'v9UBd4XzBxSRz8yhWKjUkFpBX4Fr2G+ImjqbePL4sAZvYw1tWL+aUQpzG8eOyMxxE703VDh9nIZULYI/uIb9HYHQoGYQ3WoUaWqtZg1x8pZP+Ad7ilUWk5ImRl57fTznNQiVdwlkS5Wgheh1yJCES570a4eujiK9OyB0ba4rKIcM',
        signatureWithAbcSalt: 'HCm0FI1jE6wQgwwi0ZwPTkGjssxAPtRh6tWXhNd2J2IoJYj9oQMMjCEElnvQFBa/l00sIsw2YV1tKyoTABaSTGV4vlJcDF+K0g/wiAf30TRUZo72DZKDNdyffDlH0wBDkNVW+F6uqdciJqBC6zz+unNh7x+FRwYaY8xhudIPXdyP',
        signatureWithCustomPrng: 'AGyN8xu+0yfCR1tyB9mCXcTGb2vdLnsX9ro2Qy5KV6Hw5YMVNltAt65dKR4Y8pfu6D4WUyyJRUtJ8td2ZHYzIVtWY6bG1xFt5rkjTVg4v1tzQgUQq8AHvRE2qLzwDXhazJ1e6Id2Nuxb1uInFyRC6/gLmiPga1WRDEVvFenuIA48'
      }];
      for(var i = 0; i < tests.length; ++i) {
        createTests(tests[i]);
      }

      it('should ensure maximum message length for a 1024-bit key is exceeded', function() {
        /* For PKCS#1 v1.5, the message must be padded with at least eight bytes,
          two zero bytes and one byte telling what the block type is. This is 11
          extra bytes are added to the message. The test uses a message of 118
          bytes.Together with the 11 extra bytes the encryption block needs to be
          at least 129 bytes long. This requires a key of 1025-bits. */
        var key = PKI.publicKeyFromPem(tests[0].publicKeyPem);
        var message = UTIL.createBuffer().fillWithByte(0, 118);
        ASSERT.throws(function() {
          key.encrypt(message.getBytes());
        });
      });

      it('should ensure maximum message length for a 1025-bit key is not exceeded', function() {
        var key = PKI.publicKeyFromPem(tests[1].publicKeyPem);
        var message = UTIL.createBuffer().fillWithByte(0, 118);
        ASSERT.doesNotThrow(function() {
          key.encrypt(message.getBytes());
        });
      });

      /**
       * Creates RSA encryption & decryption tests.
       *
       * Uses different key sizes (1024, 1025, 1031, 1032). The test functions are
       * generated from "templates" below, one for each key size to provide sensible
       * output.
       *
       * Key material in was created with OpenSSL using these commands:
       *
       * openssl genrsa -out rsa_1024_private.pem 1024
       * openssl rsa -in rsa_1024_private.pem -out rsa_1024_public.pem \
       *   -outform PEM -pubout
       * echo 'too many secrets' | openssl rsautl -encrypt \
       *   -inkey rsa_1024_public.pem -pubin -out rsa_1024_encrypted.bin
       *
       * echo -n 'just testing' | openssl dgst -sha1 -binary > tosign.sha1
       * openssl pkeyutl -sign -in tosign.sha1 -inkey rsa_1024_private.pem \
       *   -out rsa_1024_sig.bin -pkeyopt digest:sha1
       * openssl pkeyutl -sign -in tosign.sha1 -inkey rsa_1024_private.pem \
       *   -out rsa_1024_sigpss.bin -pkeyopt digest:sha1 \
       *   -pkeyopt rsa_padding_mode:pss -pkeyopt rsa_pss_saltlen:20
       *
       * OpenSSL commands for signature verification:
       *
       * openssl pkeyutl -verify -in tosign.sha1 -sigfile rsa_1024_sig.bin \
       *   -pubin -inkey rsa_1024_public.pem -pkeyopt digest:sha1
       * openssl pkeyutl -verify -in tosign.sha1 -sigfile rsa_1025_sigpss.bin \
       *   -pubin -inkey rsa_1025_public.pem -pkeyopt digest:sha1 \
       *   -pkeyopt rsa_padding_mode:pss -pkeyopt rsa_pss_saltlen:20
       */
      function createTests(params) {
        var keySize = params.keySize;

        it('should rsa encrypt using a ' + keySize + '-bit key', function() {
          var message = 'it need\'s to be about 20% cooler'; // it need's better grammar too

          /* First step, do public key encryption */
          var key = PKI.publicKeyFromPem(params.publicKeyPem);
          var data = key.encrypt(message);

          /* Second step, use private key decryption to verify successful
            encryption. The encrypted message differs every time, since it is
            padded with random data. Therefore just rely on the decryption
            routine to work, which is tested seperately against an externally
            provided encrypted message. */
          key = PKI.privateKeyFromPem(params.privateKeyPem);
          ASSERT.equal(key.decrypt(data), message);
        });

        it('should rsa decrypt using a ' + keySize + '-bit key', function() {
          var data = UTIL.decode64(params.encrypted);
          var key = PKI.privateKeyFromPem(params.privateKeyPem);
          ASSERT.equal(key.decrypt(data), 'too many secrets\n');
        });

        it('should rsa sign using a ' + keySize + '-bit key and PKCS#1 v1.5 padding', function() {
          var key = PKI.privateKeyFromPem(params.privateKeyPem);

          var md = MD.sha1.create();
          md.start();
          md.update('just testing');

          var signature = UTIL.decode64(params.signature);
          ASSERT.equal(key.sign(md), signature);
        });

        it('should verify an rsa signature using a ' + keySize + '-bit key and PKCS#1 v1.5 padding', function() {
          var signature = UTIL.decode64(params.signature);
          var key = PKI.publicKeyFromPem(params.publicKeyPem);

          var md = MD.sha1.create();
          md.start();
          md.update('just testing');

          ASSERT.equal(key.verify(md.digest().getBytes(), signature), true);
        });

        /* Note: signatures are *not* deterministic (the point of RSASSA-PSS),
          so they can't be compared easily -- instead they are just verified
          using the verify() function which is tested against OpenSSL-generated
          signatures. */
        it('should rsa sign using a ' + keySize + '-bit key and PSS padding', function() {
          var privateKey = PKI.privateKeyFromPem(params.privateKeyPem);
          var publicKey = PKI.publicKeyFromPem(params.publicKeyPem);

          var md = MD.sha1.create();
          md.start();
          md.update('just testing');

          // create signature
          var pss = PSS.create(
            MD.sha1.create(), MGF.mgf1.create(MD.sha1.create()), 20);
          var signature = privateKey.sign(md, pss);

          // verify signature
          md.start();
          md.update('just testing');
          ASSERT.equal(
            publicKey.verify(md.digest().getBytes(), signature, pss), true);
        });

        it('should verify an rsa signature using a ' + keySize + '-bit key and PSS padding', function() {
          var signature = UTIL.decode64(params.signaturePss);
          var key = PKI.publicKeyFromPem(params.publicKeyPem);

          var md = MD.sha1.create();
          md.start();
          md.update('just testing');

          var pss = PSS.create(
            MD.sha1.create(), MGF.mgf1.create(MD.sha1.create()), 20);
          ASSERT.equal(
            key.verify(md.digest().getBytes(), signature, pss), true);
        });

        it('should rsa sign using a ' + keySize + '-bit key and PSS padding using pss named-param API', function() {
          var privateKey = PKI.privateKeyFromPem(params.privateKeyPem);
          var publicKey = PKI.publicKeyFromPem(params.publicKeyPem);

          var md = MD.sha1.create();
          md.start();
          md.update('just testing');

          // create signature
          var pss = PSS.create({
            md: MD.sha1.create(),
            mgf: MGF.mgf1.create(MD.sha1.create()),
            saltLength: 20
          });
          var signature = privateKey.sign(md, pss);

          // verify signature
          md.start();
          md.update('just testing');
          ASSERT.equal(
            publicKey.verify(md.digest().getBytes(), signature, pss), true);
        });

        it('should verify an rsa signature using a ' + keySize + '-bit key and PSS padding using pss named-param API', function() {
          var signature = UTIL.decode64(params.signaturePss);
          var key = PKI.publicKeyFromPem(params.publicKeyPem);

          var md = MD.sha1.create();
          md.start();
          md.update('just testing');

          var pss = PSS.create({
            md: MD.sha1.create(),
            mgf: MGF.mgf1.create(MD.sha1.create()),
            saltLength: 20
          });
          ASSERT.equal(
            key.verify(md.digest().getBytes(), signature, pss), true);
        });

        it('should rsa sign using a ' + keySize + '-bit key and PSS padding using salt "abc"', function() {
          var privateKey = PKI.privateKeyFromPem(params.privateKeyPem);

          var md = MD.sha1.create();
          md.start();
          md.update('just testing');

          // create signature
          var pss = PSS.create({
            md: MD.sha1.create(),
            mgf: MGF.mgf1.create(MD.sha1.create()),
            salt: UTIL.createBuffer('abc')
          });
          var signature = privateKey.sign(md, pss);
          var b64 = UTIL.encode64(signature);
          ASSERT.equal(b64, params.signatureWithAbcSalt);
        });

        it('should verify an rsa signature using a ' + keySize + '-bit key and PSS padding using salt "abc"', function() {
          var signature = UTIL.decode64(params.signatureWithAbcSalt);
          var key = PKI.publicKeyFromPem(params.publicKeyPem);

          var md = MD.sha1.create();
          md.start();
          md.update('just testing');

          var pss = PSS.create({
            md: MD.sha1.create(),
            mgf: MGF.mgf1.create(MD.sha1.create()),
            saltLength: 3
          });
          ASSERT.equal(
            key.verify(md.digest().getBytes(), signature, pss), true);
        });

        it('should rsa sign using a ' + keySize + '-bit key and PSS padding using custom PRNG', function() {
          var prng = RANDOM.createInstance();
          prng.seedFileSync = function(needed) {
            return UTIL.fillString('a', needed);
          };
          var privateKey = PKI.privateKeyFromPem(params.privateKeyPem);

          var md = MD.sha1.create();
          md.start();
          md.update('just testing');

          // create signature
          var pss = PSS.create({
            md: MD.sha1.create(),
            mgf: MGF.mgf1.create(MD.sha1.create()),
            saltLength: 20,
            prng: prng
          });
          var signature = privateKey.sign(md, pss);
          var b64 = UTIL.encode64(signature);
          ASSERT.equal(b64, params.signatureWithCustomPrng);
        });

        it('should verify an rsa signature using a ' + keySize + '-bit key and PSS padding using custom PRNG', function() {
          var prng = RANDOM.createInstance();
          prng.seedFileSync = function(needed) {
            return UTIL.fillString('a', needed);
          };
          var signature = UTIL.decode64(params.signatureWithCustomPrng);
          var key = PKI.publicKeyFromPem(params.publicKeyPem);

          var md = MD.sha1.create();
          md.start();
          md.update('just testing');

          var pss = PSS.create({
            md: MD.sha1.create(),
            mgf: MGF.mgf1.create(MD.sha1.create()),
            saltLength: 20,
            prng: prng
          });
          ASSERT.equal(
            key.verify(md.digest().getBytes(), signature, pss), true);
        });
      }
    })();

    describe('signature verification', function() {

      // NOTE: Tests in this section, and associated fixes, are largely derived
      // from a detailed vulnerability report provided by Moosa Yahyazadeh
      // (moosa-yahyazadeh@uiowa.edu).

      // params for tests

      // public modulus / 256 bytes
      var N = new JSBN.BigInteger(
        'E932AC92252F585B3A80A4DD76A897C8B7652952FE788F6EC8DD640587A1EE56' +
        '47670A8AD4C2BE0F9FA6E49C605ADF77B5174230AF7BD50E5D6D6D6D28CCF0A8' +
        '86A514CC72E51D209CC772A52EF419F6A953F3135929588EBE9B351FCA61CED7' +
        '8F346FE00DBB6306E5C2A4C6DFC3779AF85AB417371CF34D8387B9B30AE46D7A' +
        '5FF5A655B8D8455F1B94AE736989D60A6F2FD5CADBFFBD504C5A756A2E6BB5CE' +
        'CC13BCA7503F6DF8B52ACE5C410997E98809DB4DC30D943DE4E812A47553DCE5' +
        '4844A78E36401D13F77DC650619FED88D8B3926E3D8E319C80C744779AC5D6AB' +
        'E252896950917476ECE5E8FC27D5F053D6018D91B502C4787558A002B9283DA7',
        16);

      // private exponent
      var d = new JSBN.BigInteger(
        '009b771db6c374e59227006de8f9c5ba85cf98c63754505f9f30939803afc149' +
        '8eda44b1b1e32c7eb51519edbd9591ea4fce0f8175ca528e09939e48f37088a0' +
        '7059c36332f74368c06884f718c9f8114f1b8d4cb790c63b09d46778bfdc4134' +
        '8fb4cd9feab3d24204992c6dd9ea824fbca591cd64cf68a233ad0526775c9848' +
        'fafa31528177e1f8df9181a8b945081106fd58bd3d73799b229575c4f3b29101' +
        'a03ee1f05472b3615784d9244ce0ed639c77e8e212ab52abddf4a928224b6b6f' +
        '74b7114786dd6071bd9113d7870c6b52c0bc8b9c102cfe321dac357e030ed6c5' +
        '80040ca41c13d6b4967811807ef2a225983ea9f88d67faa42620f42a4f5bdbe0' +
        '3b',
        16);

      // public exponent
      var e = new JSBN.BigInteger('3');

      // hash function
      // H = SHA-256 (OID = 0x608648016503040201)

      // message
      var m = 'hello world!';

      // to-be-signed RSA PKCS#1 v1.5 signature scheme input structure
      // I

      // signature value obtained by I^d mod N
      // S

      function _checkBadTailingGarbage(publicKey, S) {
        var md = MD.sha256.create();
        md.update(m);

        ASSERT.throws(function() {
          publicKey.verify(md.digest().getBytes(), S);
        },
        /^Error: Unparsed DER bytes remain after ASN.1 parsing.$/);
      }

      function _checkBadDigestInfo(publicKey, S, skipTailingGarbage) {
        var md = MD.sha256.create();
        md.update(m);

        ASSERT.throws(function() {
          publicKey.verify(md.digest().getBytes(), S, undefined, {
            _parseAllDigestBytes: !skipTailingGarbage
          });
        },
        /^Error: ASN.1 object does not contain a valid RSASSA-PKCS1-v1_5 DigestInfo value.$/);
      }

      function _checkGoodDigestInfo(publicKey, S, skipTailingGarbage) {
        var md = MD.sha256.create();
        md.update(m);

        ASSERT.ok(publicKey.verify(md.digest().getBytes(), S, undefined, {
          _parseAllDigestBytes: !skipTailingGarbage
        }));
      }

      it('should check DigestInfo structure', function() {
        var publicKey = RSA.setPublicKey(N, e);
        // 0xff bytes stolen from padding
        // unchecked portion of PKCS#1 encoded message used to forge a
        // signature when low public exponent is being used.
        // See "Bleichenbacher's RSA signature forgery based on implementation
        // error" by Hal Finney
        // https://mailarchive.ietf.org/arch/msg/openpgp/5rnE9ZRN1AokBVj3VqblGlP63QE/

        // 91 garbage byte injected as the value of a TLV replaced digest
        // algorithm structure
        var I = UTIL.binary.hex.decode(
          '0001ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff' +
          'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff' +
          'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff' +
          'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0030' +
          '7f065b8888888888888888888888888888888888888888888888888888888888' +
          '8888888888888888888888888888888888888888888888888888888888888888' +
          '8888888888888888888888888888888888888888888888888888888888880420' +
          '7509e5bda0c762d2bac7f90d758b5b2263fa01ccbc542ab5e3df163be08e6ca9');
        var S = UTIL.binary.hex.decode(
          'e7410e05bdc38d1c72fab784be41df3d3de2ae83894d9ec86cb5fe343d5dc7d4' +
          '5df2a36fc60363faf32f0d37ab457648af40a48a6c53ae7af0575e92cb1ffc23' +
          '6d55e1325af8c71b3ac313f2630fb498b8e1546093aca1ed56026a96cb525d99' +
          '1159a2d6ccbfd5ef63ae718f8ace2469e357ccf3f6a048bbf9760f5fb36b9dd3' +
          '8fb330eab504f05078b83f5d8bd95dce8fccc6b46babd56f678300f2b39083e5' +
          '3e04e79f503358a6222f8dd66b561fea3a51ecf3be16c9e2ea6ba8aaed9fbe6b' +
          'a510ff752e4529385f759d4d6120b15f65534248ed5bbb1307a7d0a983832969' +
          '7f5fbae91f48e478dcbb77190f0d173b6cb8b1299cf4202570d25d11a7862b47');

        _checkBadDigestInfo(publicKey, S);
      });

      it('should check tailing garbage and DigestInfo [1]', function() {
        var publicKey = RSA.setPublicKey(N, e);
        // bytes stolen from padding and unchecked tailing bytes used to forge
        // a signature when low public exponent is used

        // 204 tailing garbage bytes injected after DigestInfo structure
        var I = UTIL.binary.hex.decode(
          '000100302f300b060960864801650304020104207509e5bda0c762d2bac7f90d' +
          '758b5b2263fa01ccbc542ab5e3df163be08e6ca9888888888888888888888888' +
          '8888888888888888888888888888888888888888888888888888888888888888' +
          '8888888888888888888888888888888888888888888888888888888888888888' +
          '8888888888888888888888888888888888888888888888888888888888888888' +
          '8888888888888888888888888888888888888888888888888888888888888888' +
          '8888888888888888888888888888888888888888888888888888888888888888' +
          '8888888888888888888888888888888888888888888888888888888888888888');
        var S = UTIL.binary.hex.decode(
          'c2ad2fa23c246ee98c453d69023e7ec05956b48bd0e287341ba9d342ad49b0ff' +
          'f2bcbb9adc50f1ccbfc54106305cc74a88db89ff94901a08359893a08426373e' +
          '7949a8794798233445af6c48bc6ccbe278bdeb62c31e40c3bf0014af2faadcc9' +
          'ed7885756789a5b95c2a355fbb3f04412f42e0f9ed335ab51af8f091a62aaaaf' +
          '6577422220917daaece3ca2f4e66dc4e0574356762592052b406768c31c25cf4' +
          'c1754e6da9dc3440e238c4f9b25cccc174dd1b17b027e0f9ce2763b86f0e6871' +
          '690ddd018d2e774bc968c9c6e907a000daf5044ba31a0b9eefbd7b4b1ec466d2' +
          '0bc1dd3f020cb1091af6b476416da3024ea046b09fbbbc4d2355da9a2bc6ddb9');

        _checkBadTailingGarbage(publicKey, S);
        _checkGoodDigestInfo(publicKey, S, true);
      });

      it('should check tailing garbage and DigestInfo [2]', function() {
        var publicKey = RSA.setPublicKey(N, e);
        // bytes stolen from padding and unchecked tailing bytes used to forge
        // a signature when low public exponent is used

        // 215 tailing garbage bytes injected after DigestInfo structure
        // unchecked digest algorithm structure
        // combined with earlier issue
        var I = UTIL.binary.hex.decode(
          '0001003024010004207509e5bda0c762d2bac7f90d758b5b2263fa01ccbc542a' +
          'b5e3df163be08e6ca98888888888888888888888888888888888888888888888' +
          '8888888888888888888888888888888888888888888888888888888888888888' +
          '8888888888888888888888888888888888888888888888888888888888888888' +
          '8888888888888888888888888888888888888888888888888888888888888888' +
          '8888888888888888888888888888888888888888888888888888888888888888' +
          '8888888888888888888888888888888888888888888888888888888888888888' +
          '8888888888888888888888888888888888888888888888888888888888888888');
        var S = UTIL.binary.hex.decode(
          'a7c5812d7fc0eef766a481aac18c8c48483daf9b5ffb6614bd98ebe4ecb746dd' +
          '493cf5dd2cbe16ecaa0b52109b744930eda49316605fc823fd57a68b5b2c62e8' +
          'c1b158b26e1547a2e33cdd79427d7c513f07d02261ffe43db197d8cddca2b5b4' +
          '3c1df85aaed6e91aadd44a46bff7f5c70f1acc1a193917e3908444632f30e69c' +
          'fe95d8036d3b6ad318eefd3952804f16613c969e6d13604bb4e723dfad24c42c' +
          '8d9b5b16a9f5a4b40dcf17b167d319017740f9cc0836436c14d51c3d8a697f1f' +
          'a2b65196deb5c21b1559c7dea7f598007fa7320909825009f8bf376491c298d8' +
          '155a382e967042db952e995d14b2f961e1b22f911d1b77895def1c7ef229c87e');

        _checkBadTailingGarbage(publicKey, S);
        _checkBadDigestInfo(publicKey, S, true);
      });

      it('should check tailing garbage and DigestInfo [e=3]', function() {
        // signature forged without knowledge of private key for given message
        // and low exponent e=3

        // test data computed from a script
        var N = new JSBN.BigInteger(
          '2943851338959486749023220128247883872673446416188780128906858510' +
          '0507839535636256317277708295678804401391394313946142335874609638' +
          '6660819509361141525748702240343825617847432837639613499808068190' +
          '7802897559477710338828027239284411238090037450817022107555351764' +
          '1170327441791034393719271744724924194371070527213991317221667249' +
          '0779727008421990374037994805699108447010306443226160454080397152' +
          '7839457232809919202392450307767317822761454935119120485180507635' +
          '9472439160130994385433568113626206477097769842080459156024112389' +
          '4062006872333417793816670825914214968706669312685485046743622307' +
          '25756397511775557878046572472650613407143');
        var e = new JSBN.BigInteger('3');
        var publicKey = RSA.setPublicKey(N, e);

        var S = UTIL.binary.hex.decode(
          '0000000000000000000000000000000000000000000000000000000000000000' +
          '0000000000000000000000000000000000000000000000000000000000000000' +
          '0000000000000000000000000000000000000000000000000000000000000000' +
          '0000000000000000000000000000000000000000000000000000000000000000' +
          '0000000000000000000000000000000000000000000000000000000000000000' +
          '00000000000000000000002853ccc2cd32a8d430dd3bde37e70782ac82cdb7bc' +
          'e3c044219b50aefd689c20d3b840299f28e2fde6c67c8a7f9e528ac222fae947' +
          'a6dee0d812e3c3b3452171717396e8bedc3132d92d8317e3593642640d1431ef');

        _checkBadTailingGarbage(publicKey, S);
        _checkBadDigestInfo(publicKey, S, true);
      });

      it('should check tailing garbage and DigestInfo [e=5]', function() {
        // signature forged without knowledge of private key for given message
        // and low exponent e=5

        // test data computed from a script
        var N = new JSBN.BigInteger(
          '2943851338959486749023220128247883872673446416188780128906858510' +
          '0507839535636256317277708295678804401391394313946142335874609638' +
          '6660819509361141525748702240343825617847432837639613499808068190' +
          '7802897559477710338828027239284411238090037450817022107555351764' +
          '1170327441791034393719271744724924194371070527213991317221667249' +
          '0779727008421990374037994805699108447010306443226160454080397152' +
          '7839457232809919202392450307767317822761454935119120485180507635' +
          '9472439160130994385433568113626206477097769842080459156024112389' +
          '4062006872333417793816670825914214968706669312685485046743622307' +
          '25756397511775557878046572472650613407143');
        var e = new JSBN.BigInteger('5');
        var publicKey = RSA.setPublicKey(N, e);

        var S = UTIL.binary.hex.decode(
          '0000000000000000000000000000000000000000000000000000000000000000' +
          '0000000000000000000000000000000000000000000000000000000000000000' +
          '0000000000000000000000000000000000000000000000000000000000000000' +
          '0000000000000000000000000000000000000000000000000000000000000000' +
          '0000000000000000000000000000000000000000000000000000000000000000' +
          '0000000000000000000000000000000000000000000000000000000000000000' +
          '000000000000000000000000005475fe2681d7125972bd2c2f2c7ab7b8003b03' +
          'd4a487d6dee07c14eb5212a9fe0071b93f84ba5bb4b0cfaf20c976b11d902013');

        _checkBadTailingGarbage(publicKey, S);
        _checkBadDigestInfo(publicKey, S, true);
      });

      it('should check tailing garbage and DigestInfo [e=17]', function() {
        // signature forged without knowledge of private key for given message
        // and low exponent e=17

        // test data computed from a script
        var N = new JSBN.BigInteger(
          '9283656416612985262941143827717696579056959956800096804440022580' +
          '8979605519224532102091105159037909758713334182004379540747102163' +
          '0328875171430160513961779154294247563032373839871165519961382202' +
          '8118288833646515747631246999476620608496831766892861810215014002' +
          '6197665341672524640393361361575818164897153768964295647456396149' +
          '0989544033629566558036444831495046301215543198107208071526376318' +
          '9614817392787691228850316867637768748063173527415482321108924014' +
          '0172719575883597580010690402077593789150581979877629529469651667' +
          '0437057465296389148672556848624501468669295285428387365416747516' +
          '1806526300547653933352115280843297169178217266705491556199868750' +
          '3004910766820506445410432860104193197231996634882562129969319354' +
          '2460060799067674344247887198933507132592770898312271636011037138' +
          '9847292565155151851533347436854797090854109022697775636916157198' +
          '8470890850961835279273782642105981947430594900197891694944702901' +
          '0362775778664826653636547333219983468955600305523140183269580452' +
          '7928125033990422010817859727072181449684606236639224708148897385' +
          '6473081641220112881037032407068024585466913055187295801749427746' +
          '8722193869883705529583737211815974801292292728082721785855274147' +
          '9919792200010181565600099271483749952360303834740314188025547140' +
          '4368096941701515529809239068018840617766710102093620675455198522' +
          '9636814788735090951246816765035721775759652424641736739668936540' +
          '4502328148572893125899985056273755530380627654934084609415976292' +
          '9123186604266210829116435949633497856328752368587226250956046322' +
          '5096226739991402761266388226652661345282274508037924611589455395' +
          '6555120130786293751868059518231813715612891296160287687335835654' +
          '3979850800254668550551247800296013251153132326459614458561196296' +
          '9372672455541953777622436993987703564293487820434112162562492086' +
          '8651475984366477254452308612460939500200990849949906321025068481' +
          '9019640785570574553040761725312997166593985384222496507953730319' +
          '8339986953399517682750248394628026225887174258267456078564070387' +
          '3276539895054169432261639890044193773631304665663877617572725639' +
          '9608670862191314058068741469812649057261850985814174869283757023' +
          '5128900627675422927964369356691123905362222855545719945605604307' +
          '2632528510813096225692258119794268564646732338755890857736163737' +
          '9885700134409359441713832300526017978115395080312777381770201653' +
          '4081581157881295739782000814998795398671806283018844936919299070' +
          '5625387639000374694851356996772485803653791257029031861749956519' +
          '3846941219138832785295572786934547608717304766525989212989524778' +
          '5416834855450881318585909376917039');
        var e = new JSBN.BigInteger('17');
        var publicKey = RSA.setPublicKey(N, e);

        var S = UTIL.binary.hex.decode(
          '0000000000000000000000000000000000000000000000000000000000000000' +
          '0000000000000000000000000000000000000000000000000000000000000000' +
          '0000000000000000000000000000000000000000000000000000000000000000' +
          '0000000000000000000000000000000000000000000000000000000000000000' +
          '0000000000000000000000000000000000000000000000000000000000000000' +
          '0000000000000000000000000000000000000000000000000000000000000000' +
          '0000000000000000000000000000000000000000000000000000000000000000' +
          '0000000000000000000000000000000000000000000000000000000000000000' +
          '0000000000000000000000000000000000000000000000000000000000000000' +
          '0000000000000000000000000000000000000000000000000000000000000000' +
          '0000000000000000000000000000000000000000000000000000000000000000' +
          '0000000000000000000000000000000000000000000000000000000000000000' +
          '0000000000000000000000000000000000000000000000000000000000000000' +
          '0000000000000000000000000000000000000000000000000000000000000000' +
          '0000000000000000000000000000000000000000000000000000000000000000' +
          '0000000000000000000000000000000000000000000000000000000000000000' +
          '0000000000000000000000000000000000000000000000000000000000000000' +
          '0000000000000000000000000000000000000000000000000000000000000000' +
          '0000000000000000000000000000000000000000000000000000000000000000' +
          '0000000000000000000000000000000000000000000000000000000000000000' +
          '0000000000000000000000000000000000000000000000000000000000000000' +
          '0000000000000000000000000000000000000000000000000000000000000000' +
          '0000000000000000000000000000000000000000000000000000000000000000' +
          '0000000000000000000000000000000000000000000000000000000000000000' +
          '0000000000000000000000000000000000000000000000000000000000000000' +
          '0000000000000000000000000000000000000000000000000000000000000000' +
          '0000000000000000000000000000000000000000000000000000000000000000' +
          '0000000000000000000000000000000000000000000000000000000000000000' +
          '0000000000000000000000000000000000000000000000000000000000000000' +
          '0000000000000000000000000000000000000000000000000000000000000000' +
          '00000001eb90acbec1bf590ba1e50960db8381fb5bdc363d46379d09956560a6' +
          '16b88616ce7fa4309dc45f47f5fa47d61bf66baa3d11732ce71768ded295f962');

        _checkBadTailingGarbage(publicKey, S);
        _checkBadDigestInfo(publicKey, S, true);
      });

      it('should check DigestInfo type octet [1]', function() {
        var publicKey = RSA.setPublicKey(N, e);
        // incorrect value for digest algorithm's type octet
        // 0x0c instead of correct 0x06
        var I = UTIL.binary.hex.decode(
          '0001ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff' +
          'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff' +
          'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff' +
          'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff' +
          'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff' +
          'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff' +
          'ffffffffffffffffffffffff0030310c0d060960864801650304020105000420' +
          '7509e5bda0c762d2bac7f90d758b5b2263fa01ccbc542ab5e3df163be08e6ca9');
        var S = UTIL.binary.hex.decode(
          'd8298a199e1b6ac18f3c0067a004bd9ff7af87be6ad857d73cc3d24ef06195b8' +
          '2aaddb0194f8e61fc31453b9163062255e8baf9c480200d0991a5f764f63d5f6' +
          'afd283b9cd6afe54f0b7f738707b4eb6b8807539bb627e74db87a50413ab18e5' +
          '04e37975aad1edc612bc8ecad53b81ea249deb5a2acc27e6419c61ab9acec660' +
          '8f5ae6a2985ba0b6f42d831bc6cce4b044864154b935cf179967d129e0ad8eda' +
          '9bfbb638121c3ff13c64d439632e62250d4be928a3deb112ef76a025c5d91805' +
          '1e601878eac0049fc9d82be9ae3475deb7ca515c830c20b91b7bedf2184fef66' +
          'aea0bde62ccd1659afbfd1342322b095309451b1a87e007e640e368fb68a13c9');

        _checkBadDigestInfo(publicKey, S);
      });

      it('should check DigestInfo type octet [2]', function() {
        var publicKey = RSA.setPublicKey(N, e);
        // incorrect value for hash value's type octet
        // 0x0a instead of correct 0x04
        var I = UTIL.binary.hex.decode(
          '0001ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff' +
          'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff' +
          'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff' +
          'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff' +
          'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff' +
          'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff' +
          'ffffffffffffffffffffffff003031300d060960864801650304020105000a20' +
          '7509e5bda0c762d2bac7f90d758b5b2263fa01ccbc542ab5e3df163be08e6ca9');
        var S = UTIL.binary.hex.decode(
          'c1acdd3aef5f0439c254980295fc0d81b628df00726310a1041d79b5dd94c11d' +
          '3bcaf0236763c77c25d9ab49522ed2a7d6ea3a4e483a29838acd48f2d60a7902' +
          '75f4cd46e4b1d09c527a426ec373e8a21746ad3ea541d3b85ba4c303ff793ea8' +
          'a0a3458e93a7ec42ed66f675d7c299b0817ac95f7f45b2f48c09b3c070171f31' +
          'a33ac789da9943da5dabcda1c95b42531d45484ac1efde0fe0519077debb9318' +
          '3e63de8f80d7f3cbfecb03cbb44ac4a2d56699e33fca0663b79ca627755fc4fc' +
          '684b4ab358a0b4ac5b7e9d0cc18b6ab6300b40781502a1c03d34f31dd19d8119' +
          '5f8a44bc03a2595a706f06f0cb39b8e3f4afe06675fe7439b057f1200a06f4fd');

        _checkBadDigestInfo(publicKey, S);
      });
    });
  });
})();
