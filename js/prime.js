/**
 * Prime number generation API.
 *
 * @author Dave Longley
 *
 * Copyright (c) 2014 Digital Bazaar, Inc.
 */
(function() {
/* ########## Begin module implementation ########## */
function initModule(forge) {

// forge.prime already defined
if(forge.prime) {
  return;
}

/* PRIME API */
var prime = forge.prime = forge.prime || {};

var BigInteger = forge.jsbn.BigInteger;

// primes are 30k+i for i = 1, 7, 11, 13, 17, 19, 23, 29
var GCD_30_DELTA = [6, 4, 2, 4, 2, 4, 6, 2];
var THIRTY = new BigInteger(null);
THIRTY.fromInt(30);
var op_or = function(x,y) {return x|y;};

/**
 * Generates a random probable prime with the given number of bits.
 *
 * Alternative algorithms can be specified by name as a string or as an
 * object with custom options like so:
 *
 * {
 *   name: 'PRIMEINC',
 *   options: {
 *     maxBlockTime: <the maximum amount of time to block the main
 *       thread before allowing I/O other JS to run>
 *     workers: <the number of Web Workers to use, -1 to optimize>
 *   }
 * }
 *
 * @param bits the number of bits for the prime number.
 * @param options the options to use.
 *          [algorithm] the algorithm to use (default: 'PRIMEINC').
 *          [prng] a custom crypto-secure pseudo-random number generator to use,
 *            that must define "getBytesSync".
 *
 * @return callback(err, num) called once the operation completes.
 */
prime.generateProbablePrime = function(bits, options, callback) {
  if(typeof options === 'function') {
    callback = options;
    options = {};
  }
  options = options || {};

  // default to PRIMEINC algorithm
  var algorithm = options.algorithm || 'PRIMEINC';
  if(typeof algorithm === 'string') {
    algorithm = {name: algorithm};
  }
  algorithm.options = algorithm.options || {};

  // create prng with api that matches BigInteger secure random
  options = options || {};
  options.prng = options.prng || forge.random;
  var rng = {
    // x is an array to fill with bytes
    nextBytes: function(x) {
      var b = options.prng.getBytesSync(x.length);
      for(var i = 0; i < x.length; ++i) {
        x[i] = b.charCodeAt(i);
      }
    }
  };

  if(algorithm.name === 'PRIMEINC') {
    var num = generateRandom(bits, rng);
    return primeincFindPrime(num, algorithm.options, callback);
  }

  throw new Error('Invalid prime generation algorithm: ' + options.algorithm);
};

function generateRandom(bits, rng) {
  var num = new BigInteger(bits, rng);

  // force MSB set
  var bits1 = bits - 1;
  if(!num.testBit(bits1)) {
    var op_or = function(x,y) {return x|y;};
    num.bitwiseTo(BigInteger.ONE.shiftLeft(bits1), op_or, num);
  }

  // align number on 30k+1 boundary
  num.dAddOffset(31 - num.mod(THIRTY).byteValue(), 0);

  return num;
}

function primeincFindPrime(num, options, callback) {
  /* Note: All primes are of the form 30k+i for i < 30 and gcd(30, i)=1. The
  number we are given is always aligned at 30k + 1. Each time the number is
  determined not to be prime we add to get to the next 'i', eg: if the number
  was at 30k + 1 we add 6. */
  var deltaIdx = 0;

  // get required number of MR tests
  var mrTests = getMillerRabinTests(num.bitLength());

  // find prime nearest to 'num' for maxBlockTime ms
  var maxBlockTime = 100;
  if('maxBlockTime' in options) {
    maxBlockTime = options.maxBlockTime;
  }
  var start = +new Date();
  while(maxBlockTime === -1 || (+new Date() - start < maxBlockTime)) {
    // do primality test
    if(num.isProbablePrime(mrTests)) {
      return callback(null, num);
    }
    // get next potential prime
    num.dAddOffset(GCD_30_DELTA[deltaIdx++ % 8], 0);
  }

  // keep trying (setImmediate would be better here)
  forge.util.setImmediate(function() {
    primeincFindPrime(num, options, callback);
  });
}

/**
 * Returns the required number of Miller-Rabin tests to generate a
 * prime with an error probability of (1/2)^80.
 *
 * See Handbook of Applied Cryptography Chapter 4, Table 4.4.
 *
 * @param bits the bit size.
 *
 * @return the required number of iterations.
 */
function getMillerRabinTests(bits) {
  if(bits <= 100) return 27;
  if(bits <= 150) return 18;
  if(bits <= 200) return 15;
  if(bits <= 250) return 12;
  if(bits <= 300) return 9;
  if(bits <= 350) return 8;
  if(bits <= 400) return 7;
  if(bits <= 500) return 6;
  if(bits <= 600) return 5;
  if(bits <= 800) return 4;
  if(bits <= 1250) return 3;
  return 2;
}

} // end module implementation

/* ########## Begin module wrapper ########## */
var name = 'prime';
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
define(['require', 'module', './util', './jsbn', './random'], function() {
  defineFunc.apply(null, Array.prototype.slice.call(arguments, 0));
});

})();
