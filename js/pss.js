/**
 * Javascript implementation of PKCS#1 PSS signature padding.
 *
 * @author Stefan Siegl
 *
 * Copyright (c) 2012 Stefan Siegl <stesie@brokenpipe.de>
 */
(function() {

// define forge
var forge = {};
if(typeof(window) !== 'undefined') {
  forge = window.forge = window.forge || {};
}
// define node.js module
else if(typeof(module) !== 'undefined' && module.exports) {
  forge = {
    util: require('./util')
  };
  module.exports = forge.pss = {};
}

// shortcut for PSS API
var pss = forge.pss = forge.pss || {};

/**
 * Creates a PSS signature scheme object.
 *
 * @param hash hash function to use, a Forge md instance
 * @param mgf mask generation function to use, a Forge mgf instance
 * @param sLen length of the salt in octets
 * @return a signature scheme object.
 */
pss.create = function(hash, mgf, sLen) {
  pss = {};

  /**
   * Verify PSS signature
   *
   * This function implements EMSA-PSS-VERIFY as per RFC 3447, section 9.1.2
   *
   * @param {String} mHash The message digest hash to compare against
   *   the signature.
   * @param {String} em The encoded message (RSA decryption result).
   * @param modsBits Length of the RSA modulus in bits.
   * @return true if the signature was verified, false if not.
   */
  pss.verify = function(mHash, em, modBits) {
    var i;
    var emBits = modBits - 1;
    var emLen = Math.ceil(emBits / 8);
    var hLen = hash.digestLength;

    /* c. Convert the message representative m to an encoded message EM
     *    of length emLen = (modBits - 1) / 8 octets, where modBits
     *    is the length in bits of the RSA modulus n */
    em = em.substr(-emLen);

    /* 3. If emLen < hLen + sLen + 2, output "inconsistent" and stop. */
    if(emLen < hLen + sLen + 2) {
      throw {
        message: 'Inconsistent parameters to PSS signature verification.'
      };
    }

    /* 4. If the rightmost octet of EM does not have hexadecimal value
     *    0xbc, output "inconsistent" and stop. */
    if(em.charCodeAt(emLen - 1) !== 0xbc) {
      throw {
        message: 'Encode message does not end in 0xBC.'
      };
    }

    /* 5. Let maskedDB be the leftmost emLen - hLen - 1 octets of EM, and
     *    let H be the next hLen octets. */
    var maskLen = emLen - hLen - 1;
    var maskedDB = em.substr(0, maskLen);
    var h = em.substr(maskLen, hLen);

    /* 6. If the leftmost 8emLen - emBits bits of the leftmost octet in
     *    maskedDB are not all equal to zero, output "inconsistent" and stop. */
    var mask = (0xFF00 >> (8 * emLen - emBits)) & 0xFF;
    if((maskedDB.charCodeAt(0) & mask) !== 0) {
      throw {
        message: 'Bits beyond keysize not zero as expected.'
      };
    }

    /* 7. Let dbMask = MGF(H, emLen - hLen - 1). */
    var dbMask = mgf.generate(h, maskLen);

    /* 8. Let DB = maskedDB \xor dbMask. */
    var db = '';
    for(i = 0; i < maskLen; i ++) {
      db += String.fromCharCode(maskedDB.charCodeAt(i) ^ dbMask.charCodeAt(i));
    }

    /* 9. Set the leftmost 8emLen - emBits bits of the leftmost octet
     * in DB to zero. */
    db = String.fromCharCode(db.charCodeAt(0) & ~mask) + db.substr(1);

    /* 10. If the emLen - hLen - sLen - 2 leftmost octets of DB are not zero
     * or if the octet at position emLen - hLen - sLen - 1 (the leftmost
     * position is "position 1") does not have hexadecimal value 0x01,
     * output "inconsistent" and stop. */
    var checkLen = emLen - hLen - sLen - 2;
    for(i = 0; i < checkLen; i ++) {
      if(db.charCodeAt(i) !== 0x00) {
        throw {
          message: 'Leftmost octets not zero as expected'
        };
      }
    }

    if(db.charCodeAt(checkLen) !== 0x01) {
      throw {
        message: 'Inconsistent PSS signature, 0x01 marker not found'
      };
    }

    /* 11. Let salt be the last sLen octets of DB. */
    var salt = db.substr(-sLen);

    /* 12.  Let M' = (0x)00 00 00 00 00 00 00 00 || mHash || salt */
    var m_ = new forge.util.ByteBuffer();
    m_.fillWithByte(0, 8);
    m_.putBytes(mHash);
    m_.putBytes(salt);

    /* 13. Let H' = Hash(M'), an octet string of length hLen. */
    hash.start();
    hash.update(m_.getBytes());
    var h_ = hash.digest().getBytes();

    /* 14. If H = H', output "consistent." Otherwise, output "inconsistent." */
    return h === h_;
  };

  return pss;
};

})();
