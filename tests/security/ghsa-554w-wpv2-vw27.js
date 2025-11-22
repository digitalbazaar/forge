/*
 * Regression Test for GHSA-554w-wpv2-vw27
 * Verifies that the parser enforces a maximum recursion depth
 * instead of crashing with a call stack overflow.
 */
const assert = require('assert');
const asn1 = require('../../lib/asn1');
const util = require('../../lib/util');

describe('GHSA-554w-wpv2-vw27 Security Patch', () => {
  
  function createNestedDer(depth) {
    let obj = asn1.create(asn1.Class.UNIVERSAL, asn1.Type.INTEGER, false, '\x00');
    for (let i = 0; i < depth; i++) {
      obj = asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [obj]);
    }
    return asn1.toDer(obj).getBytes();
  }

  it('should throw a manageable error when default recursion depth is exceeded', () => {
    // create a payload just above the default limit (256)
    const DANGEROUS_DEPTH = 257; 
    const der = createNestedDer(DANGEROUS_DEPTH);
    const buf = util.createBuffer(der);

    // assert that it throws the correct error
    assert.throws(() => {
      asn1.fromDer(buf, { strict: true });
    }, /ASN.1 parsing error: Max depth exceeded./);
  });

  it('should throw a manageable error when optional recursion depth is exceeded', () => {
    // create a payload just above the optional defined limit (128)
    const DANGEROUS_DEPTH = 257; 
    const der = createNestedDer(DANGEROUS_DEPTH);
    const buf = util.createBuffer(der);

    // assert that it throws the correct error
    assert.throws(() => {
      asn1.fromDer(buf, { strict: true, maxDepth: 128 });
    }, /ASN.1 parsing error: Max depth exceeded./);
  });

  it('should still parse valid nested structures within default limits', () => {
    // verify we didn't break default depth functionality
    const SAFE_DEPTH = 20; 
    const der = createNestedDer(SAFE_DEPTH);
    const buf = util.createBuffer(der);
    
    assert.doesNotThrow(() => {
      asn1.fromDer(buf, { strict: true });
    });
  });

  it('should still parse valid nested structures within optional limits', () => {
    // verify we didn't break optional depth functionality
    const SAFE_DEPTH = 20; 
    const der = createNestedDer(SAFE_DEPTH);
    const buf = util.createBuffer(der);
    
    assert.doesNotThrow(() => {
      asn1.fromDer(buf, { strict: true, maxDepth: 128 });
    });
  });
});