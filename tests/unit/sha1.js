import ASSERT from 'assert';
import SHA1 from '../../lib/sha1.js';
import * as UTIL from '../../lib/util.js';

(function() {
  describe('sha1', function() {
    it('should have correct digest length', function() {
      var md = SHA1.create();
      ASSERT.equal(md.digestLength, 20);
    });

    it('should digest the empty string', function() {
      var md = SHA1.create();
      ASSERT.equal(
        md.digest().toHex(), 'da39a3ee5e6b4b0d3255bfef95601890afd80709');
    });

    it('should digest "abc"', function() {
      var md = SHA1.create();
      md.update('abc');
      ASSERT.equal(
        md.digest().toHex(), 'a9993e364706816aba3e25717850c26c9cd0d89d');
    });

    it('should digest "The quick brown fox jumps over the lazy dog"', function() {
      var md = SHA1.create();
      md.update('The quick brown fox jumps over the lazy dog');
      ASSERT.equal(
        md.digest().toHex(), '2fd4e1c67a2d28fced849ee1bb76e7391b93eb12');
    });

    it('should digest "c\'\u00e8"', function() {
      var md = SHA1.create();
      md.update('c\'\u00e8', 'utf8');
      ASSERT.equal(
        md.digest().toHex(), '98c9a3f804daa73b68a5660d032499a447350c0d');
    });

    it('should digest "THIS IS A MESSAGE"', function() {
      var md = SHA1.create();
      md.start();
      md.update('THIS IS ');
      md.update('A MESSAGE');
      // do twice to check continuing digest
      ASSERT.equal(
        md.digest().toHex(), '5f24f4d6499fd2d44df6c6e94be8b14a796c071d');
      ASSERT.equal(
        md.digest().toHex(), '5f24f4d6499fd2d44df6c6e94be8b14a796c071d');
    });

    it('should digest a long message', function() {
      // Note: might be too slow on old browsers
      var md = SHA1.create();
      md.update(UTIL.fillString('a', 1000000));
      ASSERT.equal(
        md.digest().toHex(), '34aa973cd4c4daa4f61eeb2bdbad27316534016f');
    });

    it('should digest multiple long messages', function() {
      // Note: might be too slow on old browsers
      // done multiple times to check hot loop optimizations
      for(var loop = 0; loop < 3; ++loop) {
        var md = SHA1.create();
        for(var i = 0; i < 10000; ++i) {
          md.update('abc');
        }
        ASSERT.equal(
          md.digest().toHex(), 'a838edb5dec47b84b4bfb0a528ea958a5d9d2350');
      }
    });
  });
})();
