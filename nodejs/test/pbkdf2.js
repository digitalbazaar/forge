(function() {

function Tests(ASSERT, PBKDF2, MD, UTIL) {
  var ByteBuffer = UTIL.ByteBuffer;

  describe('pbkdf2', function() {
    it('should derive a password with hmac-sha-1 c=1', function() {
      var dkHex = PBKDF2('password', new ByteBuffer('salt'), 1, 20).toHex();
      ASSERT.equal(dkHex, '0c60c80f961f0e71f3a9b524af6012062fe037a6');
    });

    it('should derive a password with hmac-sha-1 c=2', function() {
      var dkHex = PBKDF2('password', new ByteBuffer('salt'), 2, 20).toHex();
      ASSERT.equal(dkHex, 'ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957');
    });

    it('should derive a password with hmac-sha-1 c=5 keylen=8', function() {
      var salt = new ByteBuffer('1234567878563412', {encoding: 'hex'});
      var dkHex = PBKDF2('password', salt, 5, 8).toHex();
      ASSERT.equal(dkHex, 'd1daa78615f287e6');
    });

    it('should derive a password with hmac-sha-1 c=4096', function() {
      // Note: might be too slow on old browsers
      var dkHex = PBKDF2('password', new ByteBuffer('salt'), 4096, 20).toHex();
      ASSERT.equal(dkHex, '4b007901b765489abead49d926f721d065a429c1');
    });

    /*
    it('should derive a password with hmac-sha-1 c=16777216', function() {
      // Note: too slow
      var dkHex = PBKDF2('password', new ByteBuffer('salt'), 16777216, 20).toHex();
      ASSERT.equal(dkHex, 'eefe3d61cd4da4e4e9945b3d6ba2158c2634e984');
    });*/

    it('should derive a password with hmac-sha-256 c=1000', function() {
      // Note: might be too slow on old browsers
      var salt = new ByteBuffer(
        '4bcda0d1c689fe465c5b8a817f0ddf3d', {encoding: 'hex'});
      var md = MD.sha256.create();
      var dkHex = PBKDF2('password', salt, 1000, 48, md).toHex();
      ASSERT.equal(dkHex, '6fab493c97e4ff8de98e952dedc9841356196b71c08bd962ac48420ee6e4b4e4a26a53cdcfd866c47d40f2708dc69c75');
    });
  });
}

// check for AMD
var forge = {};
if(typeof define === 'function') {
  define([
    'forge/pbkdf2',
    'forge/md',
    'forge/util'
  ], function(PBKDF2, MD, UTIL) {
    Tests(
      // Global provided by test harness
      ASSERT,
      PBKDF2(forge),
      MD(forge),
      UTIL(forge)
    );
  });
} else if(typeof module === 'object' && module.exports) {
  // assume NodeJS
  Tests(
    require('assert'),
    require('../../js/pbkdf2')(forge),
    require('../../js/md')(forge),
    require('../../js/util')(forge));
}

})();
