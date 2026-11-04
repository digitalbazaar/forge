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

    // in Node.js the seed file is crypto.randomBytes(), which must be used as
    // raw bytes; before 1.4.4 it was decoded as UTF-8
    function _assertBinary(bytes, needed) {
      ASSERT.equal(bytes.length, needed);
      for(var i = 0; i < bytes.length; ++i) {
        ASSERT.ok(bytes.charCodeAt(i) <= 0xff);
      }
    }

    it('should get raw bytes from the Node.js seed file', function() {
      if(!UTIL.isNodejs) {
        this.skip();
      }
      _assertBinary(RANDOM.createInstance().seedFileSync(1024), 1024);
    });

    it('should get raw bytes from the async Node.js seed file',
      function(done) {
        if(!UTIL.isNodejs) {
          this.skip();
        }
        RANDOM.createInstance().seedFile(1024, function(err, bytes) {
          ASSERT.ifError(err);
          _assertBinary(bytes, 1024);
          done();
        });
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
