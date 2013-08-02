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

    (function() {
      var tests = [{
        in: '20110223123400',
        out: 1298464440000
      }, {
        in: '20110223123400.1',
        out: 1298464440100
      }, {
        in: '20110223123400.123',
        out: 1298464440123
      }];
      for(var i = 0; i < tests.length; ++i) {
        var test = tests[i];
        it('should convert local generalized time "' + test.in + '" to a Date', function() {
          var d = ASN1.generalizedTimeToDate(test.in);
          var localOffset = d.getTimezoneOffset() * 60000;
          ASSERT.equal(d.getTime(), test.out + localOffset);
        });
      }
    })();

    (function() {
      var tests = [{
        in: '20110223123400Z', // Wed Feb 23 12:34:00.000 UTC 2011
        out: 1298464440000
      }, {
        in: '20110223123400.1Z', // Wed Feb 23 12:34:00.100 UTC 2011
        out: 1298464440100
      }, {
        in: '20110223123400.123Z', // Wed Feb 23 12:34:00.123 UTC 2011
        out: 1298464440123
      }, {
        in: '20110223123400+0200', // Wed Feb 23 10:34:00.000 UTC 2011
        out: 1298457240000
      }, {
        in: '20110223123400.1+0200', // Wed Feb 23 10:34:00.100 UTC 2011
        out: 1298457240100
      }, {
        in: '20110223123400.123+0200', // Wed Feb 23 10:34:00.123 UTC 2011
        out: 1298457240123
      }, {
        in: '20110223123400-0200', // Wed Feb 23 14:34:00.000 UTC 2011
        out: 1298471640000
      }, {
        in: '20110223123400.1-0200', // Wed Feb 23 14:34:00.100 UTC 2011
        out: 1298471640100
      }, {
        in: '20110223123400.123-0200', // Wed Feb 23 14:34:00.123 UTC 2011
        out: 1298471640123
      }];
      for(var i = 0; i < tests.length; ++i) {
        var test = tests[i];
        it('should convert utc generalized time "' + test.in + '" to a Date', function() {
          var d = ASN1.generalizedTimeToDate(test.in);
          ASSERT.equal(d.getTime(), test.out);
        });
      }
    })();

    (function() {
      var tests = [{
        in: '1102231234Z', // Wed Feb 23 12:34:00 UTC 2011
        out: 1298464440000
      }, {
        in: '1102231234+0200', // Wed Feb 23 10:34:00 UTC 2011
        out: 1298457240000
      }, {
        in: '1102231234-0200', // Wed Feb 23 14:34:00 UTC 2011
        out: 1298471640000
      }, {
        in: '110223123456Z', // Wed Feb 23 12:34:56 UTC 2011
        out: 1298464496000
      }, {
        in: '110223123456+0200', // Wed Feb 23 10:34:56 UTC 2011
        out: 1298457296000
      }, {
        in: '110223123456-0200', // Wed Feb 23 14:34:56 UTC 2011
        out: 1298471696000
      }];
      for(var i = 0; i < tests.length; ++i) {
        var test = tests[i];
        it('should convert utc time "' + test.in + '" to a Date', function() {
          var d = ASN1.utcTimeToDate(test.in);
          ASSERT.equal(d.getTime(), test.out);
        });
      }
    })();
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
