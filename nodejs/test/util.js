(function() {

function Tests(ASSERT, UTIL) {
  describe('util', function() {
    it('should put bytes into a buffer', function() {
      var b = UTIL.createBuffer();
      b.putByte(1);
      b.putByte(2);
      b.putByte(3);
      b.putByte(4);
      b.putInt32(4);
      b.putByte(1);
      b.putByte(2);
      b.putByte(3);
      b.putInt32(4294967295);
      var hex = b.toHex();
      ASSERT.equal(hex, '0102030400000004010203ffffffff');

      var bytes = [];
      while(b.length() > 0) {
        bytes.push(b.getByte());
      }
      ASSERT.deepEqual(
        bytes, [1, 2, 3, 4, 0, 0, 0, 4, 1, 2, 3, 255, 255, 255, 255]);
    });

    it('should convert bytes from hex', function() {
      var hex = '0102030400000004010203ffffffff';
      var b = UTIL.createBuffer();
      b.putBytes(UTIL.hexToBytes(hex));
      ASSERT.equal(b.toHex(), hex);
    });

    it('should base64 encode some bytes', function() {
      var s1 = '00010203050607080A0B0C0D0F1011121415161719';
      var s2 = 'MDAwMTAyMDMwNTA2MDcwODBBMEIwQzBEMEYxMDExMTIxNDE1MTYxNzE5';
      ASSERT.equal(UTIL.encode64(s1), s2);
    });

    it('should base64 decode some bytes', function() {
      var s1 = '00010203050607080A0B0C0D0F1011121415161719';
      var s2 = 'MDAwMTAyMDMwNTA2MDcwODBBMEIwQzBEMEYxMDExMTIxNDE1MTYxNzE5';
      ASSERT.equal(UTIL.decode64(s2), s1);
    });
  });
}

// check for AMD
if(typeof define === 'function') {
  define([
    'forge/util'
  ], function(UTIL) {
    Tests(
      // Global provided by test harness
      ASSERT,
      UTIL()
    );
  });
}
// assume NodeJS
else if(typeof module === 'object' && module.exports) {
  Tests(
    require('assert'),
    require('../../js/util')());
}

})();
