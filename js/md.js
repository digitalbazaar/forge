/**
 * MessageDigest base API.
 *
 * @author Dave Longley
 *
 * Copyright (c) 2015 Digital Bazaar, Inc.
 */
(function() {
/* ########## Begin module implementation ########## */
function initModule(forge) {

forge.md = forge.md || {};

// registered algorithms
forge.md.algorithms = forge.md.algorithms || {};

var ByteBuffer = forge.util.ByteBuffer;
var _padding = null;

/**
 * Creates a message digest object using the given algorithm. The algorithm
 * may be provided as a string value for a previously registered algorithm or
 * it may be given as a message digest algorithm API object.
 *
 * @param algorithm the algorithm to use, either a string or an algorithm API
 *          object.
 *
 * @return the message digest object.
 */
forge.md.createMessageDigest = function(algorithm) {
  var api = algorithm;
  if(typeof api === 'string') {
    api = forge.md.getAlgorithm(api);
  }
  if(!api) {
    throw new Error('Unsupported algorithm: ' + algorithm);
  }

  // TODO: initialize _padding elsewhere, this method is only called
  // in backwards-compatibility mode and _padding is needed regardless of
  // entry point

  // TODO: change _padding to buffer
  if(!_padding || _padding.length < api.blockSize) {
    // create shared padding
    _padding = String.fromCharCode(128);
    _padding += forge.util.fillString(
      String.fromCharCode(0x00), api.blockSize);
  }

  return new forge.md.MessageDigest({
    algorithm: api
  });
};

/**
 * Registers an algorithm by name. If the name was already registered, the
 * algorithm API object will be overwritten.
 *
 * @param name the name of the algorithm.
 * @param algorithm the algorithm API object.
 */
forge.md.registerAlgorithm = function(name, algorithm) {
  forge.md.algorithms[name] = algorithm;

  // FIXME: backwards compatibility
  if(!('create' in algorithm)) {
    algorithm.create = function() {
      return forge.md.createMessageDigest(algorithm);
    };
  }
  forge.md[name] = algorithm;
};

/**
 * Gets a registered algorithm by name.
 *
 * @param name the name of the algorithm.
 *
 * @return the algorithm, if found, null if not.
 */
forge.md.getAlgorithm = function(name) {
  if(name in forge.md.algorithms) {
    return forge.md.algorithms[name];
  }
  return null;
};

/**
 * Creates a new MessageDigest.
 *
 * @param options the options to use.
 *          algorithm the algorithm API.
 */
var MessageDigest = forge.md.MessageDigest = function(options) {
  this._algorithm = options.algorithm;
  // FIXME: backwards compatibility
  this.algorithm = this._algorithm.name;
  this.digestLength = this._algorithm.digestLength;
  this.blockLength = this._algorithm.blockSize;

  // start digest automatically for first time
  this.start();
};

/**
 * Starts the digest.
 *
 * @return this digest object.
 */
MessageDigest.prototype.start = function() {
  // up to 56-bit message length for convenience
  this.messageLength = 0;

  // full message length
  this.fullMessageLength = [];
  var int32s = this._algorithm.messageLengthSize / 4;
  for(var i = 0; i < int32s; ++i) {
    this.fullMessageLength.push(0);
  }

  // input buffer
  this._input = new ByteBuffer();

  // get starting state
  this.state = this._algorithm.start();

  return this;
};

/**
 * Updates the digest with the given message input. The input can be
 * a ByteBuffer or a string to be consumed using the specified-encoding.
 *
 * @param msg the message input to update with (ByteBuffer or string).
 * @param encoding the encoding to use (eg: 'utf8', 'binary',
 *          'hex', 'base64').
 *
 * @return this digest object.
 */
MessageDigest.prototype.update = function(msg, encoding) {
  // TODO: remove copy, copying is caller's responsibility
  if(msg instanceof ByteBuffer) {
    msg = msg.copy();
  } else if(!encoding) {
    throw new Error('String encoding must be specified.');
  } else {
    msg = new ByteBuffer(msg, encoding);
  }

  // update message length
  var len = msg.length();
  this.messageLength += len;
  len = [(len / 0x100000000) >>> 0, len >>> 0];
  for(var i = this.fullMessageLength.length - 1; i >= 0; --i) {
    this.fullMessageLength[i] += len[1];
    len[1] = len[0] + ((this.fullMessageLength[i] / 0x100000000) >>> 0);
    this.fullMessageLength[i] = this.fullMessageLength[i] >>> 0;
    len[0] = ((len[1] / 0x100000000) >>> 0);
  }

  // add bytes to input buffer
  this._input.putBuffer(msg);

  // digest blocks
  while(this._input.length() >= this._algorithm.blockSize) {
    this.state = this._algorithm.digest(this.state, this._input);
  }

  // compact input buffer every 2K or if empty
  if(this._input.read > 2048 || this._input.length() === 0) {
    this._input.compact();
  }

  return this;
};

/**
 * Produces the digest.
 *
 * @return a byte buffer containing the digest value.
 */
MessageDigest.prototype.digest = function() {
  // TODO: May need to better abstract padding and writing message length
  // etc. in the future, but for now popular hashes generally all work the
  // same way.

  /* Note: Here we copy the remaining bytes in the input buffer and add the
  appropriate padding. Then we do the final update on a copy of the state so
  that if the user wants to get intermediate digests they can do so. */

  /* Determine the number of bytes that must be added to the message to
  ensure its length is appropriately congruent. In other words, the data to
  be digested must be a multiple of `blockSize`. This data includes the
  message, some padding, and the length of the message. Since the length of
  the message will be encoded as `messageLengthSize` bytes, that means that
  the last segment of the data must have `blockSize` - `messageLengthSize`
  bytes of message and padding. Therefore, the length of the message plus the
  padding must be congruent to X mod `blockSize` because
  `blockSize` - `messageLengthSize` = X.

  For example, SHA-1 is congruent to 448 mod 512 and SHA-512 is congruent to
  896 mod 1024. SHA-1 uses a `blockSize` of 64 bytes (512 bits) and a
  `messageLengthSize` of 8 bytes (64 bits). SHA-512 uses a `blockSize` of
  128 bytes (1024 bits) and a `messageLengthSize` of 16 bytes (128 bits).

  In order to fill up the message length it must be filled with padding that
  begins with 1 bit followed by all 0 bits. Padding must *always* be present,
  so if the message length is already congruent, then `blockSize` padding bits
  must be added. */

  // create final block
  var finalBlock = new ByteBuffer();
  finalBlock.putBytes(this._input.bytes());

  // compute remaining size to be digested (include message length size)
  var remaining = (
    this.fullMessageLength[this.fullMessageLength.length - 1] +
    this._algorithm.messageLengthSize);

  // add padding for overflow blockSize - overflow
  // _padding starts with 1 byte with first bit is set (byte value 128), then
  // there may be up to (blockSize - 1) other pad bytes
  var overflow = remaining & (this._algorithm.blockSize - 1);
  finalBlock.putBytes(_padding.substr(0, this._algorithm.blockSize - overflow));

  // serialize message length in bits in big-endian order; since length
  // is stored in bytes we multiply by 8 and add carry from next int
  var messageLength = new ByteBuffer();
  var next, carry;
  var bits = this.fullMessageLength[0] * 8;
  for(var i = 0; i < this.fullMessageLength.length; ++i) {
    next = this.fullMessageLength[i + 1] * 8;
    carry = (next / 0x100000000) >>> 0;
    bits += carry;
    messageLength.putInt32(bits >>> 0);
    bits = next;
  }

  // write the length of the message (algorithm-specific)
  this._algorithm.writeMessageLength(finalBlock, messageLength);

  // digest final block
  var state = this._algorithm.digest(this.state.copy(), finalBlock);

  // write state to buffer
  var rval = new ByteBuffer();
  state.write(rval);
  return rval;
};

/**
 * Copies this MessageDigest in its current state.
 *
 * @return a copy of this MessageDigest.
 */
MessageDigest.prototype.copy = function() {
  var rval = new MessageDigest({
    algorithm: this._algorithm
  });
  rval.state = this.state.copy();
  return rval;
};

} // end module implementation

/* ########## Begin module wrapper ########## */
var name = 'md';
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
define(
  ['require', 'module', './util'], function() {
  defineFunc.apply(null, Array.prototype.slice.call(arguments, 0));
});
})();
