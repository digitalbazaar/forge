/**
 * PKCS#1 partial implementation.
 *
 * Implementation of "PKCS#1 v2.2: RSA-OEAP" is modified but based on the
 * following MIT and BSD licensed code:
 *
 * https://github.com/kjur/jsjws/blob/master/rsa.js:
 *
 * The 'jsjws'(JSON Web Signature JavaScript Library) License
 *
 * Copyright (c) 2012 Kenji Urushima
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 *
 * http://webrsa.cvs.sourceforge.net/viewvc/webrsa/Client/RSAES-OAEP.js?content-type=text%2Fplain:
 *
 * RSAES-OAEP.js
 * $Id: RSAES-OAEP.js,v 1.1.1.1 2003/03/19 15:37:20 ellispritchard Exp $
 * JavaScript Implementation of PKCS #1 v2.1 RSA CRYPTOGRAPHY STANDARD (RSA Laboratories, June 14, 2002)
 * Copyright (C) Ellis Pritchard, Guardian Unlimited 2003.
 * Contact: ellis@nukinetics.com
 * Distributed under the BSD License.
 *
 * Official documentation: http://www.rsa.com/rsalabs/node.asp?id=2125
 *
 * @author Evan Jones (http://evanjones.ca/)
 * @author Dave Longley
 *
 * Copyright (c) 2013-2014 Digital Bazaar, Inc.
 */
(function() {
/* ########## Begin module implementation ########## */
function initModule(forge) {

// shortcut for PKCS#1 API
var pkcs1 = forge.pkcs1 = forge.pkcs1 || {};

// shortcuts
var asn1 = forge.asn1;
var oids = forge.pki.oids;
var BigInteger = forge.jsbn.BigInteger;
var ByteBuffer = forge.util.ByteBuffer;

/**
 * I2OSP converts a nonnegative integer (BigInteger) to an octet string
 * (ByteBuffer) of the specified length. See RFC 3447 Section 4.1.
 *
 * @param x the BigInteger to convert.
 * @param len the intended length (in bytes) to output.
 *
 * @return the ByteBuffer.
 */
pkcs1.i2osp = function(x, len) {
  // if x is shorter than len, then prepend zero bytes
  // FIXME: hex conversion inefficient; write efficient translator
  var xhex = x.toString(16);
  var zeros = len - Math.ceil(xhex.length / 2);
  return new ByteBuffer()
    .fillWithByte(0x00, zeros)
    .putBytes(forge.util.hexToBytes(xhex));
};

/**
 * OS2IP converts an octet string (ByteBuffer) to a nonnegative integer
 * (BigInteger). See RFC 3447 Section 4.2.
 *
 * @param b the ByteBuffer to convert.
 *
 * @return the BigInteger.
 */
pkcs1.os2ip = function(b) {
  // FIXME: hex conversion inefficient; write efficient translator
  return new BigInteger(b.toString('hex'), 16);
};

/**
 * Encodes the given message using the given key and digest using
 * RSAES-PKCS1-v1_5. This encoding is an encryption/decryption scheme
 * standardized in PKCS#1 v1.5.
 *
 * @param key the RSA key to use.
 * @param message the message, as a ByteBuffer, to encode.
 *
 * @return the encoded message as a ByteBuffer.
 */
pkcs1.encode_rsaes = function(key, message) {
  return pkcs1.encode_eme_v1_5(key, message, 0x02);
};

/**
 * Decodes a message previously encoded via RSAES-PKCS1-v1_5.
 *
 * @param key the RSA key to use.
 * @param em the encoded message to decode, as a ByteBuffer.
 *
 * @return the decoded message, as a ByteBuffer.
 */
pkcs1.decode_rsaes = function(key, em) {
  return pkcs1.decode_eme_v1_5(key, em);
};

/**
 * Encodes the given message using the given key and digest using
 * RSASSA-PKCS1-v1_5. This encoding is a signature scheme with appendix
 * standardized in PKCS#1 v1.5.
 *
 * @param key the RSA key to use.
 * @param message the message, as a ByteBuffer, to encode.
 *
 * @return the encoded message as a ByteBuffer.
 */
pkcs1.encode_rsassa = function(key, message) {
  // FIXME: encode_emsa_v1_5 expects a message digest object
  var em = pkcs1.encode_emsa_v1_5(message);
  return pkcs1.encode_eme_v1_5(key, em, 0x01);
};

/**
 * Decodes a message previously encoded via RSASSA-PKCS1-v1_5.
 *
 * @param key the RSA key to use.
 * @param em the encoded message to decode, as a ByteBuffer.
 *
 * @return the decoded message, as a ByteBuffer.
 */
pkcs1.decode_rsassa = function(key, em) {
  var m = pkcs1.decode_eme_v1_5(key, em);
  return pkcs1.decode_emsa_v1_5(m);
};

/**
 * Encodes a message digest by wrapping it in a DigestInfo object.
 *
 * This function implements EMSA-PKCS1-v1_5-ENCODE as per RFC 3447.
 *
 * DigestInfo ::= SEQUENCE {
 *   digestAlgorithm DigestAlgorithmIdentifier,
 *   digest Digest
 * }
 *
 * DigestAlgorithmIdentifier ::= AlgorithmIdentifier
 * Digest ::= OCTET STRING
 *
 * @param md the message digest object with the hash to sign.
 *
 * @return the encoded message, as a ByteBuffer.
 */
pkcs1.encode_emsa_v1_5 = function(md) {
  // get the oid for the algorithm
  var oid;
  if(md.algorithm in oids) {
    oid = oids[md.algorithm];
  } else {
    throw new Error('Unknown message digest algorithm: ' + md.algorithm);
  }

  // create the digest info
  var digestInfo = asn1.create(
    asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, []);
  var digestAlgorithm = asn1.create(
    asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, []);
  digestAlgorithm.value.push(asn1.create(
    asn1.Class.UNIVERSAL, asn1.Type.OID, false, oid));
  digestAlgorithm.value.push(asn1.create(
    asn1.Class.UNIVERSAL, asn1.Type.NULL, false, null));
  var digest = asn1.create(
    asn1.Class.UNIVERSAL, asn1.Type.OCTETSTRING, false, md.digest());
  digestInfo.value.push(digestAlgorithm);
  digestInfo.value.push(digest);

  // encode digest info
  return asn1.toDer(digestInfo);
};

/**
 * This function decodes a message previously encoded via
 * EMSA-PKCS1-v1_5-ENCODE as per RFC 3447.
 *
 * @param em the encoded message to decode, as a ByteBuffer.
 *
 * @return the decoded message, as a ByteBuffer.
 */
pkcs1.decode_emsa_v1_5 = function(em) {
  if(!(em instanceof ByteBuffer)) {
    throw new TypeError('em must be a ByteBuffer');
  }

  // encoded is ASN.1 DER-encoded DigestInfo
  var obj = asn1.fromDer(em);
  // TODO: validate DigestInfo

  // return message digest
  return obj.value[1].value;
};

/**
 * Encodes a message using EME-PKCS1-v1_5 padding.
 *
 * @param key the RSA key to use.
 * @param m the message to encode, as a ByteBuffer.
 * @param blockType the block type to use, which can be 0x00, 0x01, or 0x02;
 *          0x01 is used by RSASSA (signing) and 0x02 is used by RSAES
 *          (encryption) and by TLS "digitally-signed" data.
 *
 * @return the encoded message as a ByteBuffer.
 */
pkcs1.encode_eme_v1_5 = function(key, m, blockType) {
  if(!(m instanceof ByteBuffer)) {
    throw new TypeError('m must be a ByteBuffer');
  }

  // TODO: use buffers throughout
  m = m.bytes();

  if(blockType !== 0x00 && blockType !== 0x01 && blockType !== 0x02) {
    throw new Error('blockType must be 0, 1, or 2.');
  }

  var eb = new ByteBuffer();

  // get the length of the modulus in bytes
  var k = Math.ceil(key.n.bitLength() / 8);

  // EME-PKCS1-v1_5 padding needs at least 11 bytes of overhead
  if(m.length > (k - 11)) {
    var error = new Error('Message is too long for EME-PKCS1-v1_5 padding.');
    error.length = m.length;
    error.max = k - 11;
    throw error;
  }

  /* A block type BT, a padding string PS, and the data D shall be
    formatted into an octet string EB, the encryption block:

    EB = 00 || BT || PS || 00 || D

    The block type BT shall be a single octet indicating the structure of
    the encryption block. For this version of the document it shall have
    value 00, 01, or 02.

    The padding string PS shall consist of k-3-||D|| octets. For block
    type 00, the octets shall have value 00; for block type 01, they
    shall have value FF; and for block type 02, they shall be
    pseudorandomly generated and nonzero. This makes the length of the
    encryption block EB equal to k.

    Notes:

    1. The leading 00 octet ensures that the encryption block, converted to
    an integer, is less than the modulus.

    2. For block type 00, the data D must begin with a nonzero octet or
    have known length so that the encryption block can be parsed unambiguously.
    For block types 01 and 02, the encryption block can be parsed unambiguously
    since the padding string PS contains no octets with value 00 and the
    padding string is separated from the data D by an octet with value 00.

    3. Block type 01 is recommended for private-key operations. Block type 01
    has the property that the encryption block, converted to an integer, is
    guaranteed to be large, which prevents certain attacks of the kind proposed
    by Desmedt and Odlyzko.

    4. Block types 01 and 02 are compatible with PEM RSA encryption of
    content-encryption keys and message digests as described in RFC 1423. */

  // build the encryption block
  eb.putByte(0x00);
  eb.putByte(blockType);

  // create the padding
  var padNum = k - 3 - m.length;
  var padByte;
  // private key op
  if(blockType === 0x00 || blockType === 0x01) {
    padByte = (blockType === 0x00 ? 0x00 : 0xFF);
    for(var i = 0; i < padNum; ++i) {
      eb.putByte(padByte);
    }
  } else {
    // public key op (or TLS "digitally-signed" signature)
    // pad with random non-zero values
    while(padNum > 0) {
      var numZeros = 0;
      var padBytes = forge.random.getBytes(padNum);
      for(var i = 0; i < padNum; ++i) {
        padByte = padBytes.charCodeAt(i);
        if(padByte === 0) {
          ++numZeros;
        } else {
          eb.putByte(padByte);
        }
      }
      padNum = numZeros;
    }
  }

  // zero followed by message
  eb.putByte(0x00);
  eb.putBytes(m);

  return eb;
};

/**
 * Decodes a message that was encoded using EME-PKCS1-v1_5 padding.
 *
 * @param key the RSA key to use.
 * @param em the message to decode, as a ByteBuffer.
 * @param ml the message length, if specified (required if block type 0x00
 *          encoding was used).
 *
 * @return the decoded bytes in a ByteBuffer.
 */
pkcs1.decode_eme_v1_5 = function(key, em, ml) {
  // get the length of the modulus in bytes
  var k = Math.ceil(key.n.bitLength() / 8);

  /* It is an error if any of the following conditions occurs:

    1. The encryption block EB cannot be parsed unambiguously.
    2. The padding string PS consists of fewer than eight octets
      or is inconsisent with the block type BT.
    3. The decryption process is a public-key operation and the block
      type BT is not 00 or 01, or the decryption process is a
      private-key operation and the block type is not 02.
   */

  // parse the encryption block
  // TODO: shouldn't need to copy here, consumer must copy if necessary
  var eb = em.copy();
  var first = eb.getByte();
  var bt = eb.getByte();
  if(first !== 0x00 || !(bt >= 0x00 && bt <= 0x02) ||
    (bt === 0x00 && typeof(ml) === 'undefined')) {
    throw new Error('Encryption block is invalid.');
  }

  var padNum = 0;
  if(bt === 0x00) {
    // check all padding bytes for 0x00
    padNum = k - 3 - ml;
    for(var i = 0; i < padNum; ++i) {
      if(eb.getByte() !== 0x00) {
        throw new Error('Encryption block is invalid.');
      }
    }
  } else if(bt === 0x01) {
    // find the first byte that isn't 0xFF, should be after all padding
    padNum = 0;
    while(eb.length() > 1) {
      if(eb.getByte() !== 0xFF) {
        --eb.read;
        break;
      }
      ++padNum;
    }
  } else if(bt === 0x02) {
    // look for 0x00 byte
    padNum = 0;
    while(eb.length() > 1) {
      if(eb.getByte() === 0x00) {
        --eb.read;
        break;
      }
      ++padNum;
    }
  }

  // zero must be 0x00 and padNum must be (k - 3 - message length)
  var zero = eb.getByte();
  if(zero !== 0x00 || padNum !== (k - 3 - eb.length())) {
    throw new Error('Encryption block is invalid.');
  }

  // FIXME: get ByteBuffer.slice?
  return new ByteBuffer().putBuffer(eb);
};

/**
 * Encodes the given message (M) using the given key, optional label (L), and
 * seed using RSAES-OAEP.
 *
 * This method does not perform RSA encryption, it only encodes the message
 * using RSAES-OAEP.
 *
 * @param key the RSA key to use.
 * @param message the message to encode.
 * @param options the options to use:
 *          label an optional label to use.
 *          seed the seed to use.
 *          md the message digest object to use, undefined for SHA-1.
 *          mgf1 optional mgf1 parameters:
 *            md the message digest object to use for MGF1.
 *
 * @return the encoded message bytes as a ByteBuffer.
 */
pkcs1.encode_rsa_oaep = function(key, message, options) {
  if(!(message instanceof ByteBuffer)) {
    throw new TypeError('message must be a ByteBuffer');
  }

  // TODO: use buffers throughout
  message = message.bytes();

  // parse arguments
  var label;
  var seed;
  var md;
  var mgf1Md;
  // legacy args (label, seed, md)
  if(typeof options === 'string') {
    label = options;
    seed = arguments[3] || undefined;
    md = arguments[4] || undefined;
  } else if(options) {
    label = options.label || undefined;
    seed = options.seed || undefined;
    md = options.md || undefined;
    if(options.mgf1 && options.mgf1.md) {
      mgf1Md = options.mgf1.md;
    }
  }

  // default OAEP to SHA-1 message digest
  if(!md) {
    md = forge.md.sha1.create();
  } else {
    md.start();
  }

  // default MGF-1 to same as OAEP
  if(!mgf1Md) {
    mgf1Md = md;
  }

  // compute length in bytes and check output
  var keyLength = Math.ceil(key.n.bitLength() / 8);
  var maxLength = keyLength - 2 * md.digestLength - 2;
  if(message.length > maxLength) {
    var error = new Error(
      'RSAES-OAEP input message length is too long; message length=' +
      message.length + ', max length=' + maxLength);
    error.length = message.length;
    error.maxLength = maxLength;
    throw error;
  }

  if(!label) {
    label = '';
  }
  md.update(label, 'binary');
  var lHash = md.digest();

  var PS = '';
  var PS_length = maxLength - message.length;
  for (var i = 0; i < PS_length; i++) {
    PS += '\x00';
  }

  var DB = lHash.getBytes() + PS + '\x01' + message;

  if(!seed) {
    // TODO: return ByteBuffer from forge.random
    seed = new ByteBuffer(forge.random.getBytes(md.digestLength), 'binary');
  } else if(seed.length() !== md.digestLength) {
    var error = new Error(
      'Invalid RSAES-OAEP seed. The seed length must match the digest ' +
      'length; seed length=' + seed.length() +
      ', digest length=' + md.digestLength);
    error.seedLength = seed.length();
    error.digestLength = md.digestLength;
    throw error;
  }

  // TODO: use buffer
  seed = seed.bytes();

  var dbMask = rsa_mgf1(seed, keyLength - md.digestLength - 1, mgf1Md);
  var maskedDB = forge.util.xorBytes(DB, dbMask, DB.length);

  var seedMask = rsa_mgf1(maskedDB, md.digestLength, mgf1Md);
  var maskedSeed = forge.util.xorBytes(seed, seedMask, seed.length);

  // return encoded message
  return new ByteBuffer('\x00' + maskedSeed + maskedDB, 'binary');
};

/**
 * Decodes the given RSAES-OAEP encoded message (EM) using the given key
 * and optional label (L).
 *
 * This method does not perform RSA decryption, it only decodes the message
 * using RSAES-OAEP.
 *
 * @param key the RSA key to use.
 * @param em the encoded message to decode.
 * @param options the options to use:
 *          label an optional label to use.
 *          md the message digest object to use for OAEP, undefined for SHA-1.
 *          mgf1 optional mgf1 parameters:
 *            md the message digest object to use for MGF1.
 *
 * @return the decoded message bytes as a ByteBuffer.
 */
pkcs1.decode_rsa_oaep = function(key, em, options) {
  if(!(em instanceof ByteBuffer)) {
    throw new TypeError('em must be a ByteBuffer');
  }

  // TODO: use buffers throughout
  em = em.bytes();

  // parse args
  var label;
  var md;
  var mgf1Md;
  // legacy args
  if(typeof options === 'string') {
    label = options;
    md = arguments[3] || undefined;
  } else if(options) {
    label = options.label || undefined;
    md = options.md || undefined;
    if(options.mgf1 && options.mgf1.md) {
      mgf1Md = options.mgf1.md;
    }
  }

  // compute length in bytes
  var keyLength = Math.ceil(key.n.bitLength() / 8);

  if(em.length !== keyLength) {
    var error = new Error('RSAES-OAEP encoded message length is invalid.');
    error.length = em.length;
    error.expectedLength = keyLength;
    throw error;
  }

  // default OAEP to SHA-1 message digest
  if(md === undefined) {
    md = forge.md.sha1.create();
  } else {
    md.start();
  }

  // default MGF-1 to same as OAEP
  if(!mgf1Md) {
    mgf1Md = md;
  }

  if(keyLength < 2 * md.digestLength + 2) {
    throw new Error('RSAES-OAEP key is too short for the hash function.');
  }

  if(!label) {
    label = '';
  }
  md.update(label, 'binary');
  var lHash = md.digest().getBytes();

  // split the message into its parts
  var y = em.charAt(0);
  var maskedSeed = em.substring(1, md.digestLength + 1);
  var maskedDB = em.substring(1 + md.digestLength);

  var seedMask = rsa_mgf1(maskedDB, md.digestLength, mgf1Md);
  var seed = forge.util.xorBytes(maskedSeed, seedMask, maskedSeed.length);

  var dbMask = rsa_mgf1(seed, keyLength - md.digestLength - 1, mgf1Md);
  var db = forge.util.xorBytes(maskedDB, dbMask, maskedDB.length);

  var lHashPrime = db.substring(0, md.digestLength);

  // constant time check that all values match what is expected
  var error = (y !== '\x00');

  // constant time check lHash vs lHashPrime
  for(var i = 0; i < md.digestLength; ++i) {
    error |= (lHash.charAt(i) !== lHashPrime.charAt(i));
  }

  // "constant time" find the 0x1 byte separating the padding (zeros) from the
  // message
  // TODO: It must be possible to do this in a better/smarter way?
  var in_ps = 1;
  var index = md.digestLength;
  for(var j = md.digestLength; j < db.length; j++) {
    var code = db.charCodeAt(j);

    var is_0 = (code & 0x1) ^ 0x1;

    // non-zero if not 0 or 1 in the ps section
    var error_mask = in_ps ? 0xfffe : 0x0000;
    error |= (code & error_mask);

    // latch in_ps to zero after we find 0x1
    in_ps = in_ps & is_0;
    index += in_ps;
  }

  if(error || db.charCodeAt(index) !== 0x1) {
    throw new Error('Invalid RSAES-OAEP padding.');
  }

  return new ByteBuffer(db.substring(index + 1), 'binary');
};

function rsa_mgf1(seed, maskLength, hash) {
  // default to SHA-1 message digest
  if(!hash) {
    hash = forge.md.sha1.create();
  }
  var t = '';
  var count = Math.ceil(maskLength / hash.digestLength);
  for(var i = 0; i < count; ++i) {
    var c = String.fromCharCode(
      (i >> 24) & 0xFF, (i >> 16) & 0xFF, (i >> 8) & 0xFF, i & 0xFF);
    hash.start();
    hash.update(seed + c, 'binary');
    t += hash.digest().getBytes();
  }
  return t.substring(0, maskLength);
}

} // end module implementation

/* ########## Begin module wrapper ########## */
var name = 'pkcs1';
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
define([
  'require',
  'module',
  './util',
  './random',
  './sha1',
  './jsbn',
  './asn1'
], function() {
  defineFunc.apply(null, Array.prototype.slice.call(arguments, 0));
});
})();
