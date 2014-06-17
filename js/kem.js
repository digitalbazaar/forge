/**
 * Javascript implementation of RSA-KEM.
 *
 * @author Lautaro Cozzani Rodriguez
 *
 * Copyright (c) 2014 Stefan Siegl <lautaro.cozzani@scytl.com>
 */
(function() {
/* ########## Begin module implementation ########## */
function initModule(forge) {

forge.kem = forge.kem || {};

/*
* @param      src      the source array.
* @param      srcPos   starting position in the source array.
* @param      dest     the destination array.
* @param      destPos  starting position in the destination data.
* @param      length   the number of array elements to be copied.
*/
function arraycopy(src, srcPos, dest, destPos, length) {
  for ( var i = 0; i<destPos; i++ ) {
    dest[i] =0;
  }
  for ( var i = 0; i<length; i++ ) {
    dest[destPos + i] = src[srcPos+i];
  }
}

function initArray(length) {
  var array = [];
  for ( var i = 0; i<length; i++ ) {
    array.push(0);
  }
  return array;
}


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

/**
* Return the passed in value as an unsigned byte array.
* 
* @param {BigInteger} value
*            value to be converted.
* @return a byte array without a leading zero byte if present in the signed
*         encoding.
*/
forge.kem.asUnsignedByteArray = function(length, value) {
  var bytes = value.toByteArray();
  if (bytes.length == length) {
    return bytes;
  }

  var start = bytes[0] == 0 ? 1 : 0;
  var count = bytes.length - start;

  if (count > length) {
    throw {message: "standard length exceeded for value"};
  }

  var tmp = initArray(length);

  arraycopy(bytes,start, tmp, tmp.length - count, count)
  return tmp;
};

forge.kem.create = function(mgf1, rnd) {

  if ( !rnd ) {
    rnd = forge.random;
  }

  var kem = {
    
    mgf1: mgf1,
    
    rnd: rnd,

    /**
    * @param {Object} key the RSA public key to encrypt
    * @param {byte[]} out the output buffer for the encapsulated key.
    * @param {int} outOff the offset for the output buffer.
    * @param {int} keyLen the length of the random session key.
    * 
    * @return the random session key.
    */
    encrypt: function(key, out, outOff, keyLen) {
      // console.log("key", key);

      //BigInteger
      var n = key.n;
      //BigInteger
      var e = key.e;

      //BigInteger
      var r =  forge.kem.createRandomInRange(forge.jsbn.BigInteger.ZERO, n.subtract(forge.jsbn.BigInteger.ONE), this.rnd);

      //byte[]
      var bytesR = forge.kem.asUnsignedByteArray(Math.floor((n.bitLength() + 7) / 8), r);

      // Encrypt the random and encode it
      var c = r.modPow(e, n);

      var bytesC = forge.kem.asUnsignedByteArray(Math.floor((n.bitLength() + 7) / 8), c);
      arraycopy(bytesC, 0, out, outOff, bytesC.length);

      // console.log("keyLen", keyLen);
      var bytesK = this.mgf1.generate(bytesR, keyLen);
      // console.log("bytesK", bytesK);

      return bytesK;
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
    decrypt: function(key, input, inputOff, inputLen, keyLen) {

      var n = key.n;
      var d = key.d;

      // Decode the input
      var bytesC = initArray(inputLen);
      arraycopy(input, inputOff, bytesC, 0, bytesC.length);
      var c = new forge.jsbn.BigInteger(bytesC);

      var r = c.modPow(d, n);
      var bytesR = forge.kem.asUnsignedByteArray(Math.floor((n.bitLength() + 7) / 8), r);

      var bytesK = this.mgf1.generate(bytesR, keyLen);

      return bytesK;
    }


  };


  return kem;
};

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
