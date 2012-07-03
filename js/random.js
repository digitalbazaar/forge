/**
 * An API for getting cryptographically-secure random bytes. The bytes are
 * generated using the Fortuna algorithm devised by Bruce Schneier and
 * Niels Ferguson.
 *
 * Getting strong random bytes is not yet easy to do in javascript. The only
 * truish random entropy that can be collected is from the mouse, keyboard, or
 * from timing with respect to page loads, etc. This generator makes a poor
 * attempt at providing random bytes when those sources haven't yet provided
 * enough entropy to initially seed or to reseed the PRNG.
 *
 * @author Dave Longley
 *
 * Copyright (c) 2009-2012 Digital Bazaar, Inc.
 */
(function($) {

// define forge
if(typeof(window) !== 'undefined') {
  var forge = window.forge = window.forge || {};
  forge.random = {};
}
// define node.js module
else if(typeof(module) !== 'undefined' && module.exports) {
  var forge = {
    aes: require('./aes'),
    md: require('./md'),
    prng: require('./prng'),
    util: require('./util')
  };
  module.exports = forge.random = {};
}

// the default prng plugin, uses AES-128
var prng_aes = {};
var _prng_aes_output = new Array(4);
var _prng_aes_buffer = forge.util.createBuffer();
prng_aes.formatKey = function(key) {
  // convert the key into 32-bit integers
  var tmp = forge.util.createBuffer(key);
  key = new Array(4);
  key[0] = tmp.getInt32();
  key[1] = tmp.getInt32();
  key[2] = tmp.getInt32();
  key[3] = tmp.getInt32();

  // return the expanded key
  return forge.aes._expandKey(key, false);
};
prng_aes.formatSeed = function(seed) {
  // convert seed into 32-bit integers
  tmp = forge.util.createBuffer(seed);
  seed = new Array(4);
  seed[0] = tmp.getInt32();
  seed[1] = tmp.getInt32();
  seed[2] = tmp.getInt32();
  seed[3] = tmp.getInt32();
  return seed;
};
prng_aes.cipher = function(key, seed) {
  forge.aes._updateBlock(key, seed, _prng_aes_output, false);
  _prng_aes_buffer.putInt32(_prng_aes_output[0]);
  _prng_aes_buffer.putInt32(_prng_aes_output[1]);
  _prng_aes_buffer.putInt32(_prng_aes_output[2]);
  _prng_aes_buffer.putInt32(_prng_aes_output[3]);
  return _prng_aes_buffer.getBytes();
};
prng_aes.increment = function(seed) {
  // FIXME: do we care about carry or signed issues?
  ++seed[3];
  return seed;
};
prng_aes.md = forge.md.sha1;

// create default prng context
var _ctx = forge.prng.create(prng_aes);

// get load time entropy
_ctx.collectInt(+new Date(), 32);

// add some entropy from navigator object
if(typeof(navigator) !== 'undefined') {
  var _navBytes = '';
  for(var key in navigator) {
    try {
      if(typeof(navigator[key]) == 'string') {
        _navBytes += navigator[key];
      }
    } catch(e) {
      /* Some navigator keys might not be accessible, e.g. the geolocation
         attribute throws an exception if touched in Mozilla chrome:// context.

         Silently ignore this and just don't use this as a source of entropy. */
    }
  }
  _ctx.collect(_navBytes);
  _navBytes = null;
}

// add mouse and keyboard collectors if jquery is available
if($) {
  // set up mouse entropy capture
  $().mousemove(function(e) {
    // add mouse coords
    _ctx.collectInt(e.clientX, 16);
    _ctx.collectInt(e.clientY, 16);
  });

  // set up keyboard entropy capture
  $().keypress(function(e) {
    _ctx.collectInt(e.charCode, 8);
  });
}

/* Random API */

/**
 * Gets random bytes. This method tries to make the bytes more
 * unpredictable by drawing from data that can be collected from
 * the user of the browser, ie mouse movement.
 *
 * @param count the number of random bytes to get.
 *
 * @return the random bytes in a string.
 */
forge.random.getBytes = function(count) {
  return _ctx.generate(count);
};

})(typeof(jQuery) !== 'undefined' ? jQuery : null);
