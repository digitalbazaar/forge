/**
 * Password-Based Key-Derivation Function #2 implementation.
 *
 * See RFC 2898 for details.
 *
 * @author Dave Longley
 *
 * Copyright (c) 2010-2012 Digital Bazaar, Inc.
 */
(function() {

// define forge
if(typeof(window) !== 'undefined') {
  var forge = window.forge = window.forge || {};
  forge.pkcs5 = {};
}
// define node.js module
else if(typeof(module) !== 'undefined' && module.exports) {
  var forge = {
    hmac: require('./hmac'),
    md: require('./md'),
    util: require('./util')
  };
  module.exports = forge.pkcs5 = {};
}

var pkcs5 = forge.pkcs5;

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
pkcs5.pbkdf2 = function(p, s, c, dkLen, md) {
  // default prf to SHA-1
  if(typeof(md) === 'undefined' || md === null) {
    md = forge.md.sha1.create();
  }

  var hLen = md.digestLength;

  /* 1. If dkLen > (2^32 - 1) * hLen, output "derived key too long" and
       stop. */
  if(dkLen > (0xFFFFFFFF * hLen)) {
    throw {
      message: 'Derived key is too long.'
    };
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
  for(var i = 1; i <= len; ++i) {
    // PRF(P, S || INT(i)) (first iteration)
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
};

})();
