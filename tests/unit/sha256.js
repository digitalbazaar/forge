import ASSERT from 'assert';
import SHA256 from '../../lib/sha256.js';
import * as UTIL from '../../lib/util.js';

(function() {
  describe('sha256', function() {
    it('should have correct digest length', function() {
      var md = SHA256.create();
      ASSERT.equal(md.digestLength, 32);
    });

    it('should digest the empty string', function() {
      var md = SHA256.create();
      ASSERT.equal(
        md.digest().toHex(),
        'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');
    });

    it('should digest "abc"', function() {
      var md = SHA256.create();
      md.update('abc');
      ASSERT.equal(
        md.digest().toHex(),
        'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
    });

    it('should digest "The quick brown fox jumps over the lazy dog"', function() {
      var md = SHA256.create();
      md.update('The quick brown fox jumps over the lazy dog');
      ASSERT.equal(
        md.digest().toHex(),
        'd7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592');
    });

    it('should digest "c\'\u00e8"', function() {
      var md = SHA256.create();
      md.update('c\'\u00e8', 'utf8');
      ASSERT.equal(
        md.digest().toHex(),
        '1aa15c717afffd312acce2217ce1c2e5dabca53c92165999132ec9ca5decdaca');
    });

    it('should digest "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"', function() {
      var md = SHA256.create();
      md.start();
      md.update('abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq');
      // do twice to check continuing digest
      ASSERT.equal(
        md.digest().toHex(),
        '248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1');
      ASSERT.equal(
        md.digest().toHex(),
        '248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1');
    });

    it('should digest a long message', function() {
      // Note: might be too slow on old browsers
      var md = SHA256.create();
      md.update(UTIL.fillString('a', 1000000));
      ASSERT.equal(
        md.digest().toHex(),
        'cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0');
    });

    it('should digest multiple long messages', function() {
      // Note: might be too slow on old browsers
      // done multiple times to check hot loop optimizations
      for(var loop = 0; loop < 3; ++loop) {
        var md = SHA256.create();
        for(var i = 0; i < 10000; ++i) {
          md.update('abc');
        }
        ASSERT.equal(
          md.digest().toHex(),
          '13b77af908a78a94f2e21cf8fc137ea16c8020873eeee7b6b96b6b0975555a02');
      }
    });
  });
})();
