/**
 * Message Digest Algorithm 5 with 128-bit digest (MD5) implementation.
 *
 * @author Dave Longley
 *
 * Copyright (c) 2010-2015 Digital Bazaar, Inc.
 */
(function() {
/* ########## Begin module implementation ########## */
function initModule(forge) {

var md5 = forge.md5 = forge.md5 || {};

// FIXME: backwards compatibility
md5.create = function() {
  return forge.md.createMessageDigest('md5');
};

md5.Algorithm = function() {
  this.name = 'md5',
  this.blockSize = 64;
  this.digestLength = 16;
  this.messageLengthSize = 8;
};

md5.Algorithm.prototype.start = function() {
  if(!_initialized) {
    _init();
  }
  return createState();
};

md5.Algorithm.prototype.writeMessageLength = function(
  finalBlock, messageLength) {
  // reverse message length to little-endian
  var reversed = [];
  while(messageLength.length() > 0) {
    reversed.push(messageLength.getInt32());
  }
  reversed.reverse();
  for(var i = 0; i < reversed.length; ++i) {
    finalBlock.putInt32Le(reversed[i]);
  }
};

md5.Algorithm.prototype.digest = function(s, input) {
  // consume 512 bit (64 byte) chunks
  var t, a, b, c, d, f, r, i;
  var len = input.length();
  while(len >= 64) {
    // initialize hash value for this chunk
    a = s.h0;
    b = s.h1;
    c = s.h2;
    d = s.h3;

    // round 1
    for(i = 0; i < 16; ++i) {
      _w[i] = input.getInt32Le();
      f = d ^ (b & (c ^ d));
      t = (a + f + _k[i] + _w[i]);
      r = _r[i];
      a = d;
      d = c;
      c = b;
      b += (t << r) | (t >>> (32 - r));
    }
    // round 2
    for(; i < 32; ++i) {
      f = c ^ (d & (b ^ c));
      t = (a + f + _k[i] + _w[_g[i]]);
      r = _r[i];
      a = d;
      d = c;
      c = b;
      b += (t << r) | (t >>> (32 - r));
    }
    // round 3
    for(; i < 48; ++i) {
      f = b ^ c ^ d;
      t = (a + f + _k[i] + _w[_g[i]]);
      r = _r[i];
      a = d;
      d = c;
      c = b;
      b += (t << r) | (t >>> (32 - r));
    }
    // round 4
    for(; i < 64; ++i) {
      f = c ^ (b | ~d);
      t = (a + f + _k[i] + _w[_g[i]]);
      r = _r[i];
      a = d;
      d = c;
      c = b;
      b += (t << r) | (t >>> (32 - r));
    }

    // update hash state
    s.h0 = (s.h0 + a) | 0;
    s.h1 = (s.h1 + b) | 0;
    s.h2 = (s.h2 + c) | 0;
    s.h3 = (s.h3 + d) | 0;

    len -= 64;
  }

  return s;
};

forge.md.registerAlgorithm('md5', new forge.md5.Algorithm());

function createState() {
  var state = {
    h0: 0x67452301,
    h1: 0xEFCDAB89,
    h2: 0x98BADCFE,
    h3: 0x10325476
  };
  state.copy = function() {
    var rval = createState();
    rval.h0 = state.h0;
    rval.h1 = state.h1;
    rval.h2 = state.h2;
    rval.h3 = state.h3;
    return rval;
  };
  state.write = function(buffer) {
    buffer.putInt32Le(state.h0);
    buffer.putInt32Le(state.h1);
    buffer.putInt32Le(state.h2);
    buffer.putInt32Le(state.h3);
  };
  return state;
}

// constant tables for calculating md5
var _g = null;
var _r = null;
var _k = null;
var _w = null;
var _initialized = false;

/**
 * Initializes the constant tables.
 */
function _init() {
  // g values
  _g = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
    1, 6, 11, 0, 5, 10, 15, 4, 9, 14, 3, 8, 13, 2, 7, 12,
    5, 8, 11, 14, 1, 4, 7, 10, 13, 0, 3, 6, 9, 12, 15, 2,
    0, 7, 14, 5, 12, 3, 10, 1, 8, 15, 6, 13, 4, 11, 2, 9];

  // rounds table
  _r = [
    7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,
    5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,
    4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,
    6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21];

  // get the result of abs(sin(i + 1)) as a 32-bit integer
  _k = new Array(64);
  for(var i = 0; i < 64; ++i) {
    _k[i] = Math.floor(Math.abs(Math.sin(i + 1)) * 0x100000000);
  }

  // word storage
  _w = new Array(16);

  // now initialized
  _initialized = true;
}

} // end module implementation

/* ########## Begin module wrapper ########## */
var name = 'md5';
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
define(['require', 'module', './util', './md'], function() {
  defineFunc.apply(null, Array.prototype.slice.call(arguments, 0));
});
})();
