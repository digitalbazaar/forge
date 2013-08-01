(function() {

function Tests(ASSERT, ASN1, UTIL) {
  describe('asn1', function() {
    // TODO: add more ASN.1 coverage
    
    it('should convert an OID to DER', function() {
      ASSERT.equal(ASN1.oidToDer('1.2.840.113549').toHex(), '2a864886f70d');
    });

    it('should convert an OID from DER', function() {
      var der = UTIL.hexToBytes('2a864886f70d');
      ASSERT.equal(ASN1.derToOid(der), '1.2.840.113549');
    });
  });
}

// check for AMD
if(typeof define === 'function') {
  define([
    'forge/asn1',
    'forge/util'
  ], function(ASN1, UTIL) {
    Tests(
      // Global provided by test harness
      ASSERT,
      ASN1(),
      UTIL()
    );
  });
}
// assume NodeJS
else if(typeof module === 'object' && module.exports) {
  Tests(
    require('assert'),
    require('../../js/asn1')(),
    require('../../js/util')());
}

})();
