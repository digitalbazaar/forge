var ASSERT = require('assert');
var MD = require('../../lib/md.all');
var MGF = require('../../lib/mgf');
var UTIL = require('../../lib/util');

(function() {
  describe('mgf1', function() {
    it('should digest the empty string', function() {
      var seed = UTIL.hexToBytes('032e45326fa859a72ec235acff929b15d1372e30b207255f0611b8f785d764374152e0ac009e509e7ba30cd2f1778e113b64e135cf4e2292c75efe5288edfda4');
      var expect = UTIL.hexToBytes('5f8de105b5e96b2e490ddecbd147dd1def7e3b8e0e6a26eb7b956ccb8b3bdc1ca975bc57c3989e8fbad31a224655d800c46954840ff32052cdf0d640562bdfadfa263cfccf3c52b29f2af4a1869959bc77f854cf15bd7a25192985a842dbff8e13efee5b7e7e55bbe4d389647c686a9a9ab3fb889b2d7767d3837eea4e0a2f04');
      var mgf = MGF.mgf1.create(MD.sha1.create());
      var result = mgf.generate(seed, expect.length);
      ASSERT.equal(result, expect);
    });
  });
})();
