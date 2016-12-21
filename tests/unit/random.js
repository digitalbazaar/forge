var ASSERT = require('assert');
var RANDOM = require('../../lib/random');
var UTIL = require('../../lib/util');

(function() {
  describe('random', function() {
    it('should generate 10 random bytes', function() {
      var random = RANDOM.createInstance();
      random.getBytes(16);
      random.getBytes(24);
      random.getBytes(32);

      var b = random.getBytes(10);
      ASSERT.equal(b.length, 10);
    });

    it('should use a synchronous seed file', function() {
      var random = RANDOM.createInstance();
      random.seedFileSync = function(needed) {
        return UTIL.fillString('a', needed);
      };
      var b = random.getBytes(10);
      ASSERT.equal(UTIL.bytesToHex(b), '80a7901a239c3e606319');
    });

    it('should use an asynchronous seed file', function(done) {
      var random = RANDOM.createInstance();
      random.seedFile = function(needed, callback) {
        callback(null, UTIL.fillString('a', needed));
      };
      random.getBytes(10, function(err, b) {
        ASSERT.equal(err, null);
        ASSERT.equal(UTIL.bytesToHex(b), '80a7901a239c3e606319');
        done();
      });
    });

    it('should collect some random bytes', function() {
      var random = RANDOM.createInstance();
      random.seedFileSync = function(needed) {
        return UTIL.fillString('a', needed);
      };
      random.collect('bbb');
      var b = random.getBytes(10);
      ASSERT.equal(UTIL.bytesToHex(b), 'ff8d213516047c94ca46');
    });
  });
})();
