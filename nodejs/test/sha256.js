(function() {

function Tests(ASSERT, SHA256, UTIL, MD) {
  describe('sha256', function() {
    it('should digest the empty string', function() {
      var md = MD.createMessageDigest('sha256');
      ASSERT.equal(
        md.digest().toHex(),
        'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');
    });

    it('should digest "abc"', function() {
      var md = MD.createMessageDigest('sha256');
      md.update('abc', 'utf8');
      ASSERT.equal(
        md.digest().toHex(),
        'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
    });

    it('should digest "The quick brown fox jumps over the lazy dog"', function() {
      var md = MD.createMessageDigest('sha256');
      md.update('The quick brown fox jumps over the lazy dog', 'utf8');
      ASSERT.equal(
        md.digest().toHex(),
        'd7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592');
    });

    it('should digest "c\'\u00e8"', function() {
      var md = MD.createMessageDigest('sha256');
      md.update("c\'\u00e8", 'utf8');
      ASSERT.equal(
        md.digest().toHex(),
        '1aa15c717afffd312acce2217ce1c2e5dabca53c92165999132ec9ca5decdaca');
    });

    it('should digest "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"', function() {
      var md = MD.createMessageDigest('sha256');
      md.start();
      md.update(
        'abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq', 'utf8');
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
      var md = MD.createMessageDigest('sha256');
      md.update(UTIL.fillString('a', 1000000), 'utf8');
      ASSERT.equal(
        md.digest().toHex(),
        'cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0');
    });
  });
}

// check for AMD
var forge = {};
if(typeof define === 'function') {
  define([
    'forge/sha256',
    'forge/util',
    'forge/md'
  ], function(SHA256, UTIL, MD) {
    Tests(
      // Global provided by test harness
      ASSERT,
      SHA256(forge),
      UTIL(forge),
      MD(forge)
    );
  });
} else if(typeof module === 'object' && module.exports) {
  // assume NodeJS
  Tests(
    require('assert'),
    require('../../js/sha256')(forge),
    require('../../js/util')(forge),
    require('../../js/md')(forge));
}

})();
