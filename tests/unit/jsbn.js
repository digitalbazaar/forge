var ASSERT = require('assert');
var JSBN = require('../../lib/jsbn');

describe.only('jsbn', function() {
  describe('GHSA-5m6q-g25r-mvwx', function() {
    // regression tests for GHSA-5m6q-g25r-mvwx
    // test BigInteger.modInverse does not infinite loop with 0 inputs.
    var BigInteger = JSBN.BigInteger;
    it('should test BigInteger(0).modInverse(0) returns 0', function() {
      var n = BigInteger.ZERO;
      var mod = BigInteger.ZERO;
      var inv = n.modInverse(mod);
      ASSERT(inv.equals(BigInteger.ZERO));
    });
    it('should test BigInteger(0).modInverse(3) returns 0', function() {
      var n = BigInteger.ZERO;
      var mod = new BigInteger('3', 10);
      var inv = n.modInverse(mod);
      ASSERT(inv.equals(BigInteger.ZERO));
    });
    it('should test BigInteger(3).modInverse(0) returns 0', function() {
      var n = new BigInteger('3', 10);
      var mod = BigInteger.ZERO;
      var inv = n.modInverse(mod);
      ASSERT(inv.equals(BigInteger.ZERO));
    });
    it('should test BigInteger(3).modInverse(3) returns 0', function() {
      var n = new BigInteger('3', 10);
      var mod = new BigInteger('3', 10);
      var inv = n.modInverse(mod);
      ASSERT(inv.equals(BigInteger.ZERO));
    });
    it('should test BigInteger(7).modInverse(20) returns 3', function() {
      var n = new BigInteger('7', 10);
      var mod = new BigInteger('20', 10);
      var inv = n.modInverse(mod);
      ASSERT(inv.equals(new BigInteger('3', 10)));
    });
  });
});
