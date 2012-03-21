/**
 * A javascript implementation of a cryptographically-secure
 * Pseudo Random Number Generator (PRNG). The Fortuna algorithm is mostly
 * followed here. SHA-1 is used instead of SHA-256.
 *
 * @author Dave Longley
 *
 * Copyright (c) 2010-2012 Digital Bazaar, Inc.
 */
(function() {

// define forge
if(typeof(window) !== 'undefined') {
  var forge = window.forge = window.forge || {};
  forge.prng = {};
}
// define node.js module
else if(typeof(module) !== 'undefined' && module.exports) {
  var forge = {
    md: require('./md'),
    util: require('./util')
  };
  forge.md.sha1.create();
  module.exports = forge.prng = {};
}

/* PRNG API */
var prng = forge.prng;

/**
 * Creates a new PRNG context.
 *
 * A PRNG plugin must be passed in that will provide:
 *
 * 1. A function that initializes the key and seed of a PRNG context. It
 *   will be given a 16 byte key and a 16 byte seed. Any key expansion
 *   or transformation of the seed from a byte string into an array of
 *   integers (or similar) should be performed.
 * 2. The cryptographic function used by the generator. It takes a key and
 *   a seed.
 * 3. A seed increment function. It takes the seed and return seed + 1.
 * 4. An api to create a message digest.
 *
 * For an example, see random.js.
 *
 * @param plugin the PRNG plugin to use.
 */
prng.create = function(plugin) {
  var ctx = {
    plugin: plugin,
    key: null,
    seed: null,
    time: null,
    // number of reseeds so far
    reseeds: 0,
    // amount of data generated so far
    generated: 0
  };

  // create 32 entropy pools (each is a message digest)
  var md = plugin.md;
  var pools = new Array(32);
  for(var i = 0; i < 32; ++i) {
    pools[i] = md.create();
  }
  ctx.pools = pools;

  // entropy pools are written to cyclically, starting at index 0
  ctx.pool = 0;

  /**
   * Generates random bytes.
   *
   * @param count the number of random bytes to generate.
   *
   * @return count random bytes as a string.
   */
  ctx.generate = function(count) {
    // do first seed if necessary
    if(ctx.key === null) {
      _reseed();
    }

    // simple generator using counter-based CBC
    var cipher = ctx.plugin.cipher;
    var increment = ctx.plugin.increment;
    var formatKey = ctx.plugin.formatKey;
    var formatSeed = ctx.plugin.formatSeed;
    var b = forge.util.createBuffer();
    while(b.length() < count) {
      // generate the random bytes
      var bytes = cipher(ctx.key, ctx.seed);
      ctx.generated += bytes.length;
      b.putBytes(bytes);

      // generate bytes for a new key and seed
      ctx.key = formatKey(cipher(ctx.key, increment(ctx.seed)));
      ctx.seed = formatSeed(cipher(ctx.key, ctx.seed));

      // if amount of data generated is greater than 1 MiB, reseed
      if(ctx.generated >= 1048576) {
        // only do reseed at most 10 times/second (every 100 ms)
        var now = +new Date();
        if(now - ctx.time < 100) {
          _reseed();
        }
      }
    }

    return b.getBytes(count);
  };

  /**
   * Private function that reseeds a generator.
   */
  function _reseed() {
    // not enough seed data... but we need to get going so just
    // be sad and add some weak random data
    if(ctx.pools[0].messageLength < 32) {
      /* Draws from Park-Miller "minimal standard" 31 bit PRNG,
      implemented with David G. Carta's optimization: with 32 bit math
      and without division (Public Domain). */
      var needed = (32 - ctx.pools[0].messageLength) << 5;
      var b = '';
      var hi, lo, next;
      var seed = Math.floor(Math.random() * 0xFFFF);
      while(b.length < needed) {
        lo = 16807 * (seed & 0xFFFF);
        hi = 16807 * (seed >> 16);
        lo += (hi & 0x7FFF) << 16;
        lo += hi >> 15;
        lo = (lo & 0x7FFFFFFF) + (lo >> 31);
        seed = lo & 0xFFFFFFFF;

        // consume lower 3 bytes of seed
        for(var i = 0; i < 3; ++i) {
          // throw in more pseudo random
          next = seed >>> (i << 3);
          next ^= Math.floor(Math.random() * 0xFF);
          b += String.fromCharCode(next & 0xFF);
        }
      }
      // will automatically reseed in collect
      ctx.collect(b);
    }
    else {
      // create a SHA-1 message digest
      var md = forge.md.sha1.create();

      // digest pool 0's entropy and restart it
      md.update(ctx.pools[0].digest().getBytes());
      ctx.pools[0].start();

      // digest the entropy of other pools whose index k meet the
      // condition '2^k mod n == 0' where n is the number of reseeds
      var k = 1;
      for(var i = 1; i < 32; ++i) {
        // prevent signed numbers from being used
        k = (k == 31) ? 2147483648 : (k << 2);
        if(k % ctx.reseeds === 0) {
          md.update(ctx.pools[i].digest().getBytes());
          ctx.pools[i].start();
        }
      }

      // get digest for key bytes and iterate again for seed bytes
      var keyBytes = md.digest().getBytes();
      md.start();
      md.update(keyBytes);
      var seedBytes = md.digest().getBytes();

      // update
      ctx.key = ctx.plugin.formatKey(keyBytes);
      ctx.seed = ctx.plugin.formatSeed(seedBytes);
      ++ctx.reseeds;
      ctx.generated = 0;
      ctx.time = +new Date();
    }
  }

  /**
   * Adds entropy to a prng ctx's accumulator.
   *
   * @param bytes the bytes of entropy as a string.
   */
  ctx.collect = function(bytes) {
    // iterate over pools distributing entropy cyclically
    var count = bytes.length;
    for(var i = 0; i < count; ++i) {
      ctx.pools[ctx.pool].update(bytes.substr(i, 1));
      ctx.pool = (ctx.pool === 31) ? 0 : ctx.pool + 1;
    }

    // do reseed if pool 0 has at least 32 bytes (enough to create a new
    // key and seed)
    if(ctx.pools[0].messageLength >= 32) {
      // only do reseed at most 10 times/second (every 100 ms)
      var now = +new Date();
      if(ctx.time === null || (now - ctx.time < 100)) {
        _reseed();
      }
    }
  };

  /**
   * Collects an integer of n bits.
   *
   * @param i the integer entropy.
   * @param n the number of bits in the integer.
   */
  ctx.collectInt = function(i, n) {
    var bytes = '';
    do {
      n -= 8;
      bytes += String.fromCharCode((i >> n) & 0xFF);
    }
    while(n > 0);
    ctx.collect(bytes);
  };

  return ctx;
};

})();
