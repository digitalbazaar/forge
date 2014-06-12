(function() {

function Tests(ASSERT, KEM, MD, MGF, RSA, UTIL) {

  function initArray(length) {
    var array = [];
    for ( var i = 0; i<length; i++ ) {
      array.push(0);
    }
    return array;
  }

  describe('kem', function() {
    it('should escrypt and decrypt', function() {
      
      var mgf = MGF.mgf1.create(MD.sha256.create());
      var kem = KEM.create(mgf);
      // console.log(kem);

      var pair = RSA.generateKeyPair(512);
      
      var out = initArray(65);
      var key1 = kem.encrypt(pair.publicKey, out, 0, 256);

      console.log("key1", key1);

      var key2 = kem.decrypt(pair.privateKey, out, 0, out.length, 256);

      console.log("key2", key2);

      ASSERT.equal(key1, key2);

    });
  });
}

// check for AMD
if(typeof define === 'function') {
  define([
    'forge/kem',
    'forge/md',
    'forge/mgf',
    'forge/rsa',
    'forge/util'
  ], function(KEM, MD, MGF, RSA, UTIL) {
    Tests(
      // Global provided by test harness
      ASSERT,
      KEM(),
      MD(),
      MGF(),
      RSA(),
      UTIL()
    );
  });
} else if(typeof module === 'object' && module.exports) {
  // assume NodeJS
  Tests(
    require('assert'),
    require('../../js/kem')(),
    require('../../js/md')(),
    require('../../js/mgf')(),
    require('../../js/rsa')(),
    require('../../js/util')());
}

})();
