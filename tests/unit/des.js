var ASSERT = require('assert');
var CIPHER = require('../../lib/cipher');
var DES = require('../../lib/des');
var UTIL = require('../../lib/util');

(function() {
  describe('des', function() {
    // OpenSSL equivalent:
    // openssl enc -des-ecb -K a1c06b381adf3651 -nosalt
    it('should des-ecb encrypt: foobar', function() {
      var key = new UTIL.createBuffer(
        UTIL.hexToBytes('a1c06b381adf3651'));

      var cipher = CIPHER.createCipher('DES-ECB', key);
      cipher.start();
      cipher.update(UTIL.createBuffer('foobar'));
      cipher.finish();
      ASSERT.equal(cipher.output.toHex(), 'b705ffcf3dff06b3');
    });

    // OpenSSL equivalent:
    // openssl enc -d -des-ecb -K a1c06b381adf3651 -nosalt
    it('should des-ecb decrypt: b705ffcf3dff06b3', function() {
      var key = new UTIL.createBuffer(
        UTIL.hexToBytes('a1c06b381adf3651'));

      var decipher = CIPHER.createDecipher('DES-ECB', key);
      decipher.start();
      decipher.update(UTIL.createBuffer(UTIL.hexToBytes('b705ffcf3dff06b3')));
      decipher.finish();
      ASSERT.equal(decipher.output.getBytes(), 'foobar');
    });

    it('should check des-cbc short IV', function() {
      var key = new UTIL.createBuffer(
        UTIL.hexToBytes('a1c06b381adf3651'));
      var iv = new UTIL.createBuffer(
        UTIL.hexToBytes('818bcf76efc596'));

      var error = null;
      try {
        var cipher = CIPHER.createCipher('DES-CBC', key);
        cipher.start({iv: iv});
      } catch(e) {
        error = e;
      }
      ASSERT.ok(error, 'blocksize check should have failed');
    });

    // OpenSSL equivalent:
    // openssl enc -des -K a1c06b381adf3651 -iv 818bcf76efc59662 -nosalt
    it('should des-cbc encrypt: foobar', function() {
      var key = new UTIL.createBuffer(
        UTIL.hexToBytes('a1c06b381adf3651'));
      var iv = new UTIL.createBuffer(
        UTIL.hexToBytes('818bcf76efc59662'));

      var cipher = CIPHER.createCipher('DES-CBC', key);
      cipher.start({iv: iv});
      cipher.update(UTIL.createBuffer('foobar'));
      cipher.finish();
      ASSERT.equal(cipher.output.toHex(), '3261e5839a990454');
    });

    // OpenSSL equivalent:
    // openssl enc -d -des -K a1c06b381adf3651 -iv 818bcf76efc59662 -nosalt
    it('should des-cbc decrypt: 3261e5839a990454', function() {
      var key = new UTIL.createBuffer(
        UTIL.hexToBytes('a1c06b381adf3651'));
      var iv = new UTIL.createBuffer(
        UTIL.hexToBytes('818bcf76efc59662'));

      var decipher = CIPHER.createDecipher('DES-CBC', key);
      decipher.start({iv: iv});
      decipher.update(UTIL.createBuffer(UTIL.hexToBytes('3261e5839a990454')));
      decipher.finish();
      ASSERT.equal(decipher.output.getBytes(), 'foobar');
    });

    // play.golang.org/p/LX_dP0cFuEt
    it('should des-ctr encrypt: foobar', function() {
      var key = new UTIL.createBuffer(
        UTIL.hexToBytes('a1c06b381adf3651'));
      var iv = new UTIL.createBuffer(
        UTIL.hexToBytes('818bcf76efc59662'));

      var cipher = CIPHER.createCipher('DES-CTR', key);
      cipher.start({iv: iv});
      cipher.update(UTIL.createBuffer('foobar'));
      cipher.finish();
      ASSERT.equal(cipher.output.toHex(), '3a97fa79e631');
    });

    // play.golang.org/p/6_MQBYzn04c
    it('should des-ctr decrypt: foobar', function() {
      var key = new UTIL.createBuffer(
        UTIL.hexToBytes('beefdeadbeefdead'));
      var iv = new UTIL.createBuffer(
        UTIL.hexToBytes('deadbeefdeadbeef'));

      var cipher = CIPHER.createDecipher('DES-CTR', key);
      cipher.start({iv: iv});
      cipher.update(UTIL.createBuffer(UTIL.hexToBytes('6df74b7b4437')));
      cipher.finish();
      ASSERT.equal(cipher.output.getBytes(), 'foobar');
    });

    // play.golang.org/p/i892aR7YsGK
    it('should des-ctr encrypt: dead parrot', function() {
      var key = new UTIL.createBuffer(
        UTIL.hexToBytes('a1c06b381adf3651'));
      var iv = new UTIL.createBuffer(
        UTIL.hexToBytes('818bcf76efc59662'));

      var cipher = CIPHER.createCipher('DES-CTR', key);
      cipher.start({iv: iv});
      cipher.update(UTIL.createBuffer('dead parrot'));
      cipher.finish();
      ASSERT.equal(cipher.output.toHex(), '389df47fa733dcf4b99b7c');
    });

    // play.golang.org/p/6L0LqPS9ARt
    it('should des-ctr decrypt: 79f1527c5737f774f85c1a9399755d895ae7', function() {
      var key = new UTIL.createBuffer(
        UTIL.hexToBytes('beefdeadbeefdead'));
      var iv = new UTIL.createBuffer(
        UTIL.hexToBytes('deadbeefdeadbeef'));

      var cipher = CIPHER.createDecipher('DES-CTR', key);
      cipher.start({iv: iv});
      cipher.update(UTIL.createBuffer(UTIL.hexToBytes('79f1527c5737f774f85c1a9399755d895ae7')));
      cipher.finish();
      ASSERT.equal(cipher.output.getBytes(), 'riverrun, past Eve');
    });

    // play.golang.org/p/WsSx6BXJniU
    it('should des-ctr encrypt: 69742773206e6f742073696c6c7920656e6f756768', function() {
      var key = new UTIL.createBuffer(
        UTIL.hexToBytes('a1c06b381adf3651'));
      var iv = new UTIL.createBuffer(
        UTIL.hexToBytes('818bcf76efc59662'));

      var cipher = CIPHER.createCipher('DES-CTR', key);
      cipher.start({iv: iv});
      cipher.update(UTIL.createBuffer(UTIL.hexToBytes('69742773206e6f742073696c6c7920656e6f756768')));
      cipher.finish();
      ASSERT.equal(cipher.output.toHex(), '358cb268a72dd2f2eb87615060bd3a490e85136873');
    });

    // play.golang.org/p/y01inAlMCEM
    it('should des-ctr decrypt: 0a80bd81a4dc1303a62f', function() {
      var key = new UTIL.createBuffer(
        UTIL.hexToBytes('beefdeadbeefdead'));
      var iv = new UTIL.createBuffer(
        UTIL.hexToBytes('deadbeefdeadbeef'));

      var cipher = CIPHER.createDecipher('DES-CTR', key);
      cipher.start({iv: iv});
      cipher.update(UTIL.createBuffer(UTIL.hexToBytes('0a80bd81a4dc1303a62f')));
      cipher.finish();
      ASSERT.equal(cipher.output.toHex(), '01189998819991197253');
    });

    // OpenSSL equivalent:
    // openssl enc -des-ede3 -K a1c06b381adf36517e84575552777779da5e3d9f994b05b5 -nosalt
    it('should 3des-ecb encrypt: foobar', function() {
      var key = new UTIL.createBuffer(
        UTIL.hexToBytes('a1c06b381adf36517e84575552777779da5e3d9f994b05b5'));

      var cipher = CIPHER.createCipher('3DES-ECB', key);
      cipher.start();
      cipher.update(UTIL.createBuffer('foobar'));
      cipher.finish();
      ASSERT.equal(cipher.output.toHex(), 'fce8b1ee8c6440d1');
    });

    // OpenSSL equivalent:
    // openssl enc -d -des-ede3 -K a1c06b381adf36517e84575552777779da5e3d9f994b05b5 -nosalt
    it('should 3des-ecb decrypt: fce8b1ee8c6440d1', function() {
      var key = new UTIL.createBuffer(
        UTIL.hexToBytes('a1c06b381adf36517e84575552777779da5e3d9f994b05b5'));

      var decipher = CIPHER.createDecipher('3DES-ECB', key);
      decipher.start();
      decipher.update(UTIL.createBuffer(UTIL.hexToBytes('fce8b1ee8c6440d1')));
      decipher.finish();
      ASSERT.equal(decipher.output.getBytes(), 'foobar');
    });

    // OpenSSL equivalent:
    // openssl enc -des3 -K a1c06b381adf36517e84575552777779da5e3d9f994b05b5 -iv 818bcf76efc59662 -nosalt
    it('should 3des-cbc encrypt "foobar", restart, and encrypt "foobar,,"', function() {
      var key = new UTIL.createBuffer(
        UTIL.hexToBytes('a1c06b381adf36517e84575552777779da5e3d9f994b05b5'));
      var iv = new UTIL.createBuffer(
        UTIL.hexToBytes('818bcf76efc59662'));

      var cipher = CIPHER.createCipher('3DES-CBC', key);
      cipher.start({iv: iv.copy()});
      cipher.update(UTIL.createBuffer('foobar'));
      cipher.finish();
      ASSERT.equal(cipher.output.toHex(), '209225f7687ca0b2');

      cipher.start({iv: iv.copy()});
      cipher.update(UTIL.createBuffer('foobar,,'));
      cipher.finish();
      ASSERT.equal(cipher.output.toHex(), '57156174c48dfc37293831bf192a6742');
    });

    // OpenSSL equivalent:
    // openssl enc -d -des3 -K a1c06b381adf36517e84575552777779da5e3d9f994b05b5 -iv 818bcf76efc59662 -nosalt
    it('should 3des-cbc decrypt "209225f7687ca0b2", restart, and decrypt "57156174c48dfc37293831bf192a6742,,"', function() {
      var key = new UTIL.createBuffer(
        UTIL.hexToBytes('a1c06b381adf36517e84575552777779da5e3d9f994b05b5'));
      var iv = new UTIL.createBuffer(
        UTIL.hexToBytes('818bcf76efc59662'));

      var decipher = CIPHER.createDecipher('3DES-CBC', key);
      decipher.start({iv: iv.copy()});
      decipher.update(UTIL.createBuffer(UTIL.hexToBytes('209225f7687ca0b2')));
      decipher.finish();
      ASSERT.equal(decipher.output.getBytes(), 'foobar');

      decipher.start({iv: iv.copy()});
      decipher.update(
        UTIL.createBuffer(UTIL.hexToBytes('57156174c48dfc37293831bf192a6742')));
      decipher.finish();
      ASSERT.equal(decipher.output.getBytes(), 'foobar,,');
    });
  });
})();
