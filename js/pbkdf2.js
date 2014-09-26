/**
 * Password-Based Key-Derivation Function #2 implementation.
 *
 * See RFC 2898 for details.
 *
 * @author Dave Longley
 *
 * Copyright (c) 2010-2013 Digital Bazaar, Inc.
 */
(function() {
/* ########## Begin module implementation ########## */
function initModule(forge) {

var pkcs5 = forge.pkcs5 = forge.pkcs5 || {};

/**
 * Derives a key from a password.
 *
 * @param p the password as a string of bytes.
 * @param s the salt as a string of bytes.
 * @param c the iteration count, a positive integer.
 * @param dkLen the intended length, in bytes, of the derived key,
 *          (max: 2^32 - 1) * hash length of the PRF.
 * @param md the message digest to use in the PRF, defaults to SHA-1.
 *
 * @return the derived key, as a string of bytes.
 */
forge.pbkdf2 = pkcs5.pbkdf2 = function(p, s, c, dkLen, md, callback) {
  if(typeof md === 'function') {
    callback = md;
    md = null;
  }
  // default prf to SHA-1
  if(typeof md === 'undefined' || md === null) {
    md = forge.md.sha1.create();
  }

  var hLen = md.digestLength;

  /* 1. If dkLen > (2^32 - 1) * hLen, output "derived key too long" and
    stop. */
  if(dkLen > (0xFFFFFFFF * hLen)) {
    var err = new Error('Derived key is too long.');
    if(callback) {
      return callback(err);
    }
    throw err;
  }

  /* 2. Let len be the number of hLen-octet blocks in the derived key,
    rounding up, and let r be the number of octets in the last
    block:

    len = CEIL(dkLen / hLen),
    r = dkLen - (len - 1) * hLen. */
  var len = Math.ceil(dkLen / hLen);
  var r = dkLen - (len - 1) * hLen;

  /* 3. For each block of the derived key apply the function F defined
    below to the password P, the salt S, the iteration count c, and
    the block index to compute the block:

    T_1 = F(P, S, c, 1),
    T_2 = F(P, S, c, 2),
    ...
    T_len = F(P, S, c, len),

    where the function F is defined as the exclusive-or sum of the
    first c iterates of the underlying pseudorandom function PRF
    applied to the password P and the concatenation of the salt S
    and the block index i:

    F(P, S, c, i) = u_1 XOR u_2 XOR ... XOR u_c

    where

    u_1 = PRF(P, S || INT(i)),
    u_2 = PRF(P, u_1),
    ...
    u_c = PRF(P, u_{c-1}).

    Here, INT(i) is a four-octet encoding of the integer i, most
    significant octet first. */
  var prf = forge.hmac.create();
  prf.start(md, p);
  var dk = '';
  var xor, u_c, u_c1;

  // sync version
  if(!callback) {
    for(var i = 1; i <= len; ++i) {
      // PRF(P, S || INT(i)) (first iteration)
      prf.start(null, null);
      prf.update(s);
      prf.update(forge.util.int32ToBytes(i));
      xor = u_c1 = prf.digest().getBytes();

      // PRF(P, u_{c-1}) (other iterations)
      for(var j = 2; j <= c; ++j) {
        prf.start(null, null);
        prf.update(u_c1);
        u_c = prf.digest().getBytes();
        // F(p, s, c, i)
        xor = forge.util.xorBytes(xor, u_c, hLen);
        u_c1 = u_c;
      }

      /* 4. Concatenate the blocks and extract the first dkLen octets to
        produce a derived key DK:

        DK = T_1 || T_2 ||  ...  || T_len<0..r-1> */
      dk += (i < len) ? xor : xor.substr(0, r);
    }
    /* 5. Output the derived key DK. */
    return dk;
  }

  // async version
  var i = 1, j;
  function outer() {
    if(i > len) {
      // done
      return callback(null, dk);
    }

    // PRF(P, S || INT(i)) (first iteration)
    prf.start(null, null);
    prf.update(s);
    prf.update(forge.util.int32ToBytes(i));
    xor = u_c1 = prf.digest().getBytes();

    // PRF(P, u_{c-1}) (other iterations)
    j = 2;
    inner();
  }

  function inner() {
    if(j <= c) {
      prf.start(null, null);
      prf.update(u_c1);
      u_c = prf.digest().getBytes();
      // F(p, s, c, i)
      xor = forge.util.xorBytes(xor, u_c, hLen);
      u_c1 = u_c;
      ++j;
      return forge.util.setImmediate(inner);
    }

    /* 4. Concatenate the blocks and extract the first dkLen octets to
      produce a derived key DK:

      DK = T_1 || T_2 ||  ...  || T_len<0..r-1> */
    dk += (i < len) ? xor : xor.substr(0, r);

    ++i;
    outer();
  }

  outer();
};

} // end module implementation

/* ########## Begin module wrapper ########## */
var name = 'pbkdf2';
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
define(['require', 'module', './hmac', './md', './util'], function() {
  defineFunc.apply(null, Array.prototype.slice.call(arguments, 0));
});
})();
