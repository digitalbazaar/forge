/**
 * Cipher base API.
 *
 * @author Dave Longley
 *
 * Copyright (c) 2010-2014 Digital Bazaar, Inc.
 */
(function() {
/* ########## Begin module implementation ########## */
function initModule(forge) {

forge.cipher = forge.cipher || {};

// registered algorithms
forge.cipher.algorithms = forge.cipher.algorithms || {};

var ByteBuffer = forge.util.ByteBuffer;

/**
 * Creates a cipher object that can be used to encrypt data using the given
 * algorithm and key. The algorithm may be provided as a string value for a
 * previously registered algorithm or it may be given as a cipher algorithm
 * API object.
 *
 * @param algorithm the algorithm to use, either a string or an algorithm API
 *          object.
 * @param key the key to use, as a ByteBuffer.
 *
 * @return the cipher.
 */
forge.cipher.createCipher = function(algorithm, key) {
  var api = algorithm;
  if(typeof api === 'string') {
    api = forge.cipher.getAlgorithm(api);
    if(api) {
      api = api();
    }
  }
  if(!api) {
    throw new Error('Unsupported algorithm: ' + algorithm);
  }

  if(!(key instanceof ByteBuffer)) {
    throw new TypeError('key must be a ByteBuffer.');
  }

  // assume block cipher
  return new forge.cipher.BlockCipher({
    algorithm: api,
    key: key,
    decrypt: false
  });
};

/**
 * Creates a decipher object that can be used to decrypt data using the given
 * algorithm and key. The algorithm may be provided as a string value for a
 * previously registered algorithm or it may be given as a cipher algorithm
 * API object.
 *
 * @param algorithm the algorithm to use, either a string or an algorithm API
 *          object.
 * @param key the key to use, as a ByteBuffer.
 *
 * @return the cipher.
 */
forge.cipher.createDecipher = function(algorithm, key) {
  var api = algorithm;
  if(typeof api === 'string') {
    api = forge.cipher.getAlgorithm(api);
    if(api) {
      api = api();
    }
  }
  if(!api) {
    throw new Error('Unsupported algorithm: ' + algorithm);
  }

  if(!(key instanceof ByteBuffer)) {
    throw new TypeError('key must be a ByteBuffer.');
  }

  // assume block cipher
  return new forge.cipher.BlockCipher({
    algorithm: api,
    key: key,
    decrypt: true
  });
};

/**
 * Registers an algorithm by name. If the name was already registered, the
 * algorithm API object will be overwritten.
 *
 * @param name the name of the algorithm.
 * @param algorithm the algorithm API object.
 */
forge.cipher.registerAlgorithm = function(name, algorithm) {
  name = name.toUpperCase();
  forge.cipher.algorithms[name] = algorithm;
};

/**
 * Gets a registered algorithm by name.
 *
 * @param name the name of the algorithm.
 *
 * @return the algorithm, if found, null if not.
 */
forge.cipher.getAlgorithm = function(name) {
  name = name.toUpperCase();
  if(name in forge.cipher.algorithms) {
    return forge.cipher.algorithms[name];
  }
  return null;
};

var BlockCipher = forge.cipher.BlockCipher = function(options) {
  this.algorithm = options.algorithm;
  this.mode = this.algorithm.mode;
  this.blockSize = this.mode.blockSize;
  this._finish = false;
  this._input = null;
  this.output = null;
  this._op = options.decrypt ? this.mode.decrypt : this.mode.encrypt;
  this._decrypt = options.decrypt;
  this.algorithm.initialize(options);
};

/**
 * Starts or restarts the encryption or decryption process, whichever
 * was previously configured.
 *
 * For non-GCM mode, the IV must be a ByteBuffer with at least 16 bytes.
 *
 * For GCM-mode, the IV must be a ByteBuffer with at least 12 bytes (96 bits)
 * as recommended by NIST SP-800-38D but another length may be given.
 *
 * @param options the options to use:
 *          iv the initialization vector to use as a ByteBuffer, null to reuse
 *            the last ciphered block from a previous update() (this
 *            "residue" method is for legacy support only and is considered
 *            insecure).
 *          additionalData additional authentication data as a ByteBuffer,
 *            for 'GCM' mode, (default: none).
 *          tagLength desired length of authentication tag, in bits, for
 *            'GCM' mode (0-128, default: 128).
 *          tag the authentication tag to check if decrypting, as a
 *             ByteBuffer.
 *          output the output ByteBuffer to write to, null to create one.
 *
 * @return this cipher for chaining.
 */
BlockCipher.prototype.start = function(options) {
  options = options || {};
  var opts = {};
  for(var key in options) {
    opts[key] = options[key];
  }
  if(opts.iv && !(opts.iv instanceof ByteBuffer)) {
    throw new TypeError('options.iv must be a ByteBuffer.');
  }
  if(opts.additionalData && !(opts.additionalData instanceof ByteBuffer)) {
    throw new TypeError('options.additionalData must be a ByteBuffer.');
  }
  if(opts.tag && !(opts.tag instanceof ByteBuffer)) {
    throw new TypeError('options.tag must be a ByteBuffer.');
  }

  opts.decrypt = this._decrypt;
  this._finish = false;
  this._input = new ByteBuffer();
  this.output = options.output || new ByteBuffer();
  this.mode.start(opts);

  return this;
};

/**
 * Updates the next block according to the cipher mode.
 *
 * @param input the ByteBuffer to read from.
 *
 * @return this cipher for chaining.
 */
BlockCipher.prototype.update = function(input) {
  if(!this._finish) {
    // not finishing, so fill the input buffer with more input
    if(!(input instanceof ByteBuffer)) {
      throw new TypeError('input must be a ByteBuffer.');
    }
    this._input.putBuffer(input);
  }

  // do cipher operation while input contains full blocks or if finishing
  while(this._input.length() >= this.blockSize ||
    (this._input.length() > 0 && this._finish)) {
    this._op.call(this.mode, this._input, this.output);
  }

  // free consumed memory from input buffer
  this._input.compact();

  return this;
};

/**
 * Finishes encrypting or decrypting.
 *
 * @param pad a padding function to use in CBC mode, null for default,
 *          signature(blockSize, buffer, decrypt).
 *
 * @return true if successful, false on error.
 */
BlockCipher.prototype.finish = function(pad) {
  // backwards-compatibility w/deprecated padding API
  // Note: will overwrite padding functions even after another start() call
  if(pad && this.mode.name === 'CBC') {
    this.mode.pad = function(input) {
      return pad(this.blockSize, input, false);
    };
    this.mode.unpad = function(output) {
      return pad(this.blockSize, output, true);
    };
  }

  // build options for padding and afterFinish functions
  var options = {};
  options.decrypt = this._decrypt;

  // get # of bytes that won't fill a block
  options.overflow = this._input.length() % this.blockSize;

  if(!this._decrypt && this.mode.pad) {
    if(!this.mode.pad(this._input, options)) {
      return false;
    }
  }

  // do final update
  this._finish = true;
  this.update();

  if(this._decrypt && this.mode.unpad) {
    if(!this.mode.unpad(this.output, options)) {
      return false;
    }
  }

  if(this.mode.afterFinish) {
    if(!this.mode.afterFinish(this.output, options)) {
      return false;
    }
  }

  return true;
};


} // end module implementation

/* ########## Begin module wrapper ########## */
var name = 'cipher';
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
define(['require', 'module', './util'], function() {
  defineFunc.apply(null, Array.prototype.slice.call(arguments, 0));
});
})();
