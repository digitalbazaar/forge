/**
 * Javascript implementation of Basic KDF generator for derived keys as defined by ISO 18033 <br>
 * This implementation is based on ISO 18033.
 *
 * @author Lautaro Cozzani Rodriguez
 *
 * Copyright (c) 2014 Lautaro Cozzani <lautaro.cozzani@scytl.com>
 */
(function() {
/* ########## Begin module implementation ########## */
function initModule(forge) {

forge.kdf = forge.kdf || {};

forge.kdf.createKdf1 = function(digest) {
  return forge.kdf.create(0,digest, digest.digestLength)
}


forge.kdf.create = function(md, digestLength) {
  digestLength = digestLength || md.digestLength;
  var mgf = {
    /**
     * Generate mask of specified length.
     *
     * @param {String} seed The seed for mask generation.
     * @param maskLen Number of bytes to generate.
     * @return {String} The generated mask.
     */
    generate: function(seed, maskLen) {
      /* 2. Let T be the empty octet string. */
      var t = new forge.util.ByteBuffer();

      /* 3. For counter from 0 to ceil(maskLen / hLen), do the following: */
      var len = Math.ceil((maskLen + digestLength - 1) / digestLength);
      
      var outOffset = 0;
      var outLength = maskLen;
      for(var i = 0; i < len; i++) {
        /* a. Convert counter to an octet string C of length 4 octets */
        var c = new forge.util.ByteBuffer();
        c.putInt32(i);

        /* b. Concatenate the hash of the seed mgfSeed and C to the octet
         * string T: */
        md.start();
        md.update(seed + c.getBytes());
        var dig = md.digest();

        if (outLength > digestLength) {
            // System.arraycopy(dig, 0, out, outOffset, digestLength);
            outOffset += digestLength;
            outLength -= digestLength;
            var subDig = dig.getBytes().substr(0,digestLength); 
            t.putBytes(subDig);
        } else {
            // System.arraycopy(dig, 0, out, outOffset, outLength);
            t.putBuffer(dig);
        }
      }

      /* Output the leading maskLen octets of T as the octet string mask. */
      t.truncate(t.length() - maskLen);
      return t.getBytes();
    }
  };

  return mgf;
};

} // end module implementation

/* ########## Begin module wrapper ########## */
var name = 'kdf';
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
