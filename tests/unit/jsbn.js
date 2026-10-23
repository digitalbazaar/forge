var ASSERT = require('assert');
var JSBN = require('../../lib/jsbn');

describe('jsbn', function() {
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

  describe('GHSA-h6cr-wjv9-3cpp', function() {
    // regression tests for GHSA-h6cr-wjv9-3cpp
    // (incomplete fix of GHSA-5m6q-g25r-mvwx)
    // test BigInteger.modInverse does not infinite loop with negative inputs.
    var BigInteger = JSBN.BigInteger;
    it('should test BigInteger(-1).modInverse(7) returns 0', function() {
      var n = new BigInteger('-1', 10);
      var mod = new BigInteger('7', 10);
      var inv = n.modInverse(mod);
      ASSERT(inv.equals(BigInteger.ZERO));
    });
    it('should test BigInteger(-65537).modInverse(phi) returns 0', function() {
      var n = new BigInteger('-65537', 10);
      var mod = new BigInteger('123456789012345678901234567890', 10);
      var inv = n.modInverse(mod);
      ASSERT(inv.equals(BigInteger.ZERO));
    });
    it('should test BigInteger(3).modInverse(-7) returns 0', function() {
      var n = new BigInteger('3', 10);
      var mod = new BigInteger('-7', 10);
      var inv = n.modInverse(mod);
      ASSERT(inv.equals(BigInteger.ZERO));
    });
    it('should test BigInteger(-3).modInverse(-7) returns 0', function() {
      var n = new BigInteger('-3', 10);
      var mod = new BigInteger('-7', 10);
      var inv = n.modInverse(mod);
      ASSERT(inv.equals(BigInteger.ZERO));
    });
    it('should test BigInteger(3).modInverse(7) returns 5', function() {
      var n = new BigInteger('3', 10);
      var mod = new BigInteger('7', 10);
      var inv = n.modInverse(mod);
      ASSERT(inv.equals(new BigInteger('5', 10)));
    });
    it('should test BigInteger(10).modInverse(7) returns 5', function() {
      var n = new BigInteger('10', 10);
      var mod = new BigInteger('7', 10);
      var inv = n.modInverse(mod);
      ASSERT(inv.equals(new BigInteger('5', 10)));
    });
  });
});
