/**
 * Javascript implementation of RSA-KEM.
 *
 * @author Lautaro Cozzani Rodriguez
 * @author Dave Longley
 *
 * Copyright (c) 2014 Lautaro Cozzani <lautaro.cozzani@scytl.com>
 * Copyright (c) 2014 Digital Bazaar, Inc.
 */
(function() {
/* ########## Begin module implementation ########## */
function initModule(forge) {

forge.kem = forge.kem || {};

var MAX_ITERATIONS = 1000;

forge.kem.createRandomInRange = function(min, max, rnd) {

  if (min.bitLength() > max.bitLength() / 2) {
    return forge.kem.createRandomInRange(forge.jsbn.BigInteger.ZERO, max.subtract(min), rnd)
      .add(min);
  }

  var rng = {
    // x is an array to fill with bytes
    nextBytes: function(x) {
      var b = rnd.getBytesSync(x.length);
      for(var i = 0; i < x.length; ++i) {
        x[i] = b.charCodeAt(i);
      }
    }
  };

  for (var i = 0; i < MAX_ITERATIONS; ++i) {
    var x = new forge.jsbn.BigInteger(max.bitLength(), rng);
    if (x.compareTo(min) >= 0 && x.compareTo(max) <= 0) {
      return x;
    }
  }

  // fall back to a faster (restricted) method
  return new forge.jsbn.BigInteger(max.subtract(min).bitLength() - 1, rng)
    .add(min);
};

/*
* Convert BigInteger to string of Bytes
*/
function bnToBytes(b) {
  // prepend 0x00 if first byte >= 0x80
  var hex = b.toString(16);
  if(hex[0] >= '8') {
    hex = '00' + hex;
  }
  return forge.util.hexToBytes(hex);
}

/**
 * Creates a key derivation API object that implements KDF1 per ISO 18033-2.
 *
 * @param md the hash API to use.
 * @param [digestLength] an optional digest length that must be positive and
 *          less than or equal to md.digestLength.
 *
 * @return a KDF1 API object.
 */
forge.kem.kdf1 = function(md, digestLength) {
  _createKDF(this, md, 0, digestLength || md.digestLength);
};

/**
 * Creates a key derivation API object that implements KDF2 per ISO 18033-2.
 *
 * @param md the hash API to use.
 * @param [digestLength] an optional digest length that must be positive and
 *          less than or equal to md.digestLength.
 *
 * @return a KDF2 API object.
 */
forge.kem.kdf2 = function(md, digestLength) {
  _createKDF(this, md, 1, digestLength || md.digestLength);
};

/**
 * The API for the RSA Key Encapsulation Mechanism (RSA-KEM) from ISO 18033-2.
 */
forge.kem.rsa = {};

/**
 * Creates an RSA KEM API object for generating a secret asymmetric key.
 *
 * The symmetric key may be generated via a call to 'encrypt', which will
 * produce a ciphertext to be transmitted to the recipient and a key to be
 * kept secret. The ciphertext is a parameter to be passed to 'decrypt' which
 * will produce the same secret key for the recipient to use to decrypt a
 * message that was encrypted with the secret key.
 */
forge.kem.rsa.create = function(kdf, options) {
  options = options || {};
  var rng = options.rng || forge.random;

  var kem = {
    /**
    * @param {Object} key the RSA public key to encrypt
    * @param {byte[]} out the output buffer for the encapsulated key.
    * @param {int} outOff the offset for the output buffer.
    * @param {int} keyLen the length of the random session key.
    *
    * @return the ciphertext for generating the secret key and the secret key.
    */
    encrypt: function(key, keyLen) {
      var n = key.n;
      var e = key.e;

      // generate a random
      var r =  forge.kem.createRandomInRange(
        forge.jsbn.BigInteger.ZERO,
        n.subtract(forge.jsbn.BigInteger.ONE),
        rng);

      // FIXME: use key.encrypt
      // encrypt the random
      var c = r.modPow(e, n);
      var ciphertext = forge.util.hexToBytes(c.toString(16));

      var secretKey = kdf.generate(bnToBytes(r), keyLen);

      return {
        ciphertext: ciphertext,
        key: secretKey
      };
    },

    /**
     * Decrypt an encapsulated session key.
     *
     * @param key
     *            the RSA private key to decrypt
     * @param in
     *            the input buffer for the encapsulated key.
     * @param inOff
     *            the offset for the input buffer.
     * @param inLen
     *            the length of the encapsulated key.
     * @param keyLen
     *            the length of the session key.
     * @return the session key.
     */
    decrypt: function(key, ciphertext, keyLen) {
      var n = key.n;
      var d = key.d;

      // FIXME: use key.decrypt
      // Decode the input
      var c = new forge.jsbn.BigInteger(forge.util.bytesToHex(ciphertext), 16);

      var r = c.modPow(d, n);

      return kdf.generate(bnToBytes(r), keyLen);
    }

  };

  return kem;
};

/**
 * Creates a KDF1 or KDF2 API object.
 *
 * @param md the hash API to use.
 * @param counterStart the starting index for the counter.
 * @param digestLength the digest length to use.
 *
 * @return the KDF API object.
 */
function _createKDF(kdf, md, counterStart, digestLength) {
  /**
   * Generate a key of the specified length.
   *
   * @param x the binary-encoded byte string to generate a key from.
   * @param length the number of bytes to generate (the size of the key).
   *
   * @return the key as a binary-encoded string.
   */
  kdf.generate = function(x, length) {
    var key = new forge.util.ByteBuffer();

    // run counter from counterStart to ceil(length / Hash.len)
    var k = Math.ceil(length / digestLength) + counterStart;

    var c = new forge.util.ByteBuffer();
    for(var i = counterStart; i < k; ++i) {
      // I2OSP(i, 4): convert counter to an octet string of 4 octets
      c.putInt32(i);

      // digest 'x' and the counter and add the result to the key
      md.start();
      md.update(x + c.getBytes());
      var hash = md.digest();
      key.putBytes(hash.getBytes(digestLength));
    }

    // truncate to the correct key length
    key.truncate(key.length() - length);
    return key.getBytes();
  };
}

} // end module implementation

/* ########## Begin module wrapper ########## */
var name = 'kem';
if(typeof define !== 'function') {
  // NodeJS -> AMD
  if(typeof module === 'object' && module.exports) {
    var nodeJS = true;
    define = function(ids, factory) {
      factory(require, module);
    };
  } else {
    // <script>
    if(typeof forge === 'undefined') {
      forge = {};
    }
    return initModule(forge);
  }
}
// AMD
var deps;
var defineFunc = function(require, module) {
  module.exports = function(forge) {
    var mods = deps.map(function(dep) {
      return require(dep);
    }).concat(initModule);
    // handle circular dependencies
    forge = forge || {};
    forge.defined = forge.defined || {};
    if(forge.defined[name]) {
      return forge[name];
    }
    forge.defined[name] = true;
    for(var i = 0; i < mods.length; ++i) {
      mods[i](forge);
    }
    return forge[name];
  };
};
var tmpDefine = define;
define = function(ids, factory) {
  deps = (typeof ids === 'string') ? factory.slice(2) : ids.slice(2);
  if(nodeJS) {
    delete define;
    return tmpDefine.apply(null, Array.prototype.slice.call(arguments, 0));
  }
  define = tmpDefine;
  return define.apply(null, Array.prototype.slice.call(arguments, 0));
};
define(['require', 'module', './util','./random','./jsbn'], function() {
  defineFunc.apply(null, Array.prototype.slice.call(arguments, 0));
});
})();
