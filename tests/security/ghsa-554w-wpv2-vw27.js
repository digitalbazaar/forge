/*
 * Regression Test for GHSA-554w-wpv2-vw27
 * Verifies that the parser enforces a maximum recursion depth
 * instead of crashing with a call stack overflow.
 */
var assert = require('assert');
var asn1 = require('../../lib/asn1');
var util = require('../../lib/util');

describe('GHSA-554w-wpv2-vw27 Security Patch', function() {

  function createNestedDer(depth) {
    var obj = asn1.create(asn1.Class.UNIVERSAL, asn1.Type.INTEGER, false, '\x00');
    for(var i = 0; i < depth; i++) {
      obj = asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [obj]);
    }
    return asn1.toDer(obj).getBytes();
  }

  it('should throw a manageable error when default recursion depth is exceeded', function() {
    // create a payload just above the default limit (256)
    var DANGEROUS_DEPTH = 257;
    var der = createNestedDer(DANGEROUS_DEPTH);
    var buf = util.createBuffer(der);

    // assert that it throws the correct error
    assert.throws(function() {
      asn1.fromDer(buf, {strict: true});
    }, /ASN.1 parsing error: Max depth exceeded./);
  });

  it('should throw a manageable error when optional recursion depth is exceeded', function() {
    // create a payload just above the optional defined limit (128)
    var DANGEROUS_DEPTH = 129;
    var der = createNestedDer(DANGEROUS_DEPTH);
    var buf = util.createBuffer(der);

    // assert that it throws the correct error
    assert.throws(function() {
      asn1.fromDer(buf, {strict: true, maxDepth: 128});
    }, /ASN.1 parsing error: Max depth exceeded./);
  });

  it('should still parse valid nested structures within default limits', function() {
    // verify we didn't break default depth functionality
    var SAFE_DEPTH = 20;
    var der = createNestedDer(SAFE_DEPTH);
    var buf = util.createBuffer(der);

    asn1.fromDer(buf, {strict: true});
  });

  it('should still parse valid nested structures within optional limits', function() {
    // verify we didn't break optional depth functionality
    var SAFE_DEPTH = 20;
    var der = createNestedDer(SAFE_DEPTH);
    var buf = util.createBuffer(der);

    asn1.fromDer(buf, {strict: true, maxDepth: 128});
  });
});
