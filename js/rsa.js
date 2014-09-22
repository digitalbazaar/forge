/**
 * Javascript implementation of basic RSA algorithms.
 *
 * @author Dave Longley
 *
 * Copyright (c) 2010-2014 Digital Bazaar, Inc.
 *
 * The only algorithm currently supported for PKI is RSA.
 *
 * An RSA key is often stored in ASN.1 DER format. The SubjectPublicKeyInfo
 * ASN.1 structure is composed of an algorithm of type AlgorithmIdentifier
 * and a subjectPublicKey of type bit string.
 *
 * The AlgorithmIdentifier contains an Object Identifier (OID) and parameters
 * for the algorithm, if any. In the case of RSA, there aren't any.
 *
 * SubjectPublicKeyInfo ::= SEQUENCE {
 *   algorithm AlgorithmIdentifier,
 *   subjectPublicKey BIT STRING
 * }
 *
 * AlgorithmIdentifer ::= SEQUENCE {
 *   algorithm OBJECT IDENTIFIER,
 *   parameters ANY DEFINED BY algorithm OPTIONAL
 * }
 *
 * For an RSA public key, the subjectPublicKey is:
 *
 * RSAPublicKey ::= SEQUENCE {
 *   modulus            INTEGER,    -- n
 *   publicExponent     INTEGER     -- e
 * }
 *
 * PrivateKeyInfo ::= SEQUENCE {
 *   version                   Version,
 *   privateKeyAlgorithm       PrivateKeyAlgorithmIdentifier,
 *   privateKey                PrivateKey,
 *   attributes           [0]  IMPLICIT Attributes OPTIONAL
 * }
 *
 * Version ::= INTEGER
 * PrivateKeyAlgorithmIdentifier ::= AlgorithmIdentifier
 * PrivateKey ::= OCTET STRING
 * Attributes ::= SET OF Attribute
 *
 * An RSA private key as the following structure:
 *
 * RSAPrivateKey ::= SEQUENCE {
 *   version Version,
 *   modulus INTEGER, -- n
 *   publicExponent INTEGER, -- e
 *   privateExponent INTEGER, -- d
 *   prime1 INTEGER, -- p
 *   prime2 INTEGER, -- q
 *   exponent1 INTEGER, -- d mod (p-1)
 *   exponent2 INTEGER, -- d mod (q-1)
 *   coefficient INTEGER -- (inverse of q) mod p
 * }
 *
 * Version ::= INTEGER
 *
 * The OID for the RSA key algorithm is: 1.2.840.113549.1.1.1
 */
(function() {
function initModule(forge) {
/* ########## Begin module implementation ########## */

if(typeof BigInteger === 'undefined') {
  var BigInteger = forge.jsbn.BigInteger;
}

var ByteBuffer = forge.util.ByteBuffer;

// shortcut for asn.1 API
var asn1 = forge.asn1;

/*
 * RSA encryption and decryption, see RFC 2313.
 */
forge.pki = forge.pki || {};
forge.pki.rsa = forge.rsa = forge.rsa || {};
var pki = forge.pki;

// for finding primes, which are 30k+i for i = 1, 7, 11, 13, 17, 19, 23, 29
var GCD_30_DELTA = [6, 4, 2, 4, 2, 4, 6, 2];

// validator for a PrivateKeyInfo structure
var privateKeyValidator = {
  // PrivateKeyInfo
  name: 'PrivateKeyInfo',
  tagClass: asn1.Class.UNIVERSAL,
  type: asn1.Type.SEQUENCE,
  constructed: true,
  value: [{
    // Version (INTEGER)
    name: 'PrivateKeyInfo.version',
    tagClass: asn1.Class.UNIVERSAL,
    type: asn1.Type.INTEGER,
    constructed: false,
    capture: 'privateKeyVersion'
  }, {
    // privateKeyAlgorithm
    name: 'PrivateKeyInfo.privateKeyAlgorithm',
    tagClass: asn1.Class.UNIVERSAL,
    type: asn1.Type.SEQUENCE,
    constructed: true,
    value: [{
      name: 'AlgorithmIdentifier.algorithm',
      tagClass: asn1.Class.UNIVERSAL,
      type: asn1.Type.OID,
      constructed: false,
      capture: 'privateKeyOid'
    }]
  }, {
    // PrivateKey
    name: 'PrivateKeyInfo',
    tagClass: asn1.Class.UNIVERSAL,
    type: asn1.Type.OCTETSTRING,
    constructed: false,
    capture: 'privateKey'
  }]
};

// validator for an RSA private key
var rsaPrivateKeyValidator = {
  // RSAPrivateKey
  name: 'RSAPrivateKey',
  tagClass: asn1.Class.UNIVERSAL,
  type: asn1.Type.SEQUENCE,
  constructed: true,
  value: [{
    // Version (INTEGER)
    name: 'RSAPrivateKey.version',
    tagClass: asn1.Class.UNIVERSAL,
    type: asn1.Type.INTEGER,
    constructed: false,
    capture: {
      name: 'privateKeyVersion',
      format: 'number'
    }
  }, {
    // modulus (n)
    name: 'RSAPrivateKey.modulus',
    tagClass: asn1.Class.UNIVERSAL,
    type: asn1.Type.INTEGER,
    constructed: false,
    capture: {
      name: 'privateKeyModulus',
      format: 'buffer'
    }
  }, {
    // publicExponent (e)
    name: 'RSAPrivateKey.publicExponent',
    tagClass: asn1.Class.UNIVERSAL,
    type: asn1.Type.INTEGER,
    constructed: false,
    capture: {
      name: 'privateKeyPublicExponent',
      format: 'buffer'
    }
  }, {
    // privateExponent (d)
    name: 'RSAPrivateKey.privateExponent',
    tagClass: asn1.Class.UNIVERSAL,
    type: asn1.Type.INTEGER,
    constructed: false,
    capture: {
      name: 'privateKeyPrivateExponent',
      format: 'buffer'
    }
  }, {
    // prime1 (p)
    name: 'RSAPrivateKey.prime1',
    tagClass: asn1.Class.UNIVERSAL,
    type: asn1.Type.INTEGER,
    constructed: false,
    capture: {
      name: 'privateKeyPrime1',
      format: 'buffer'
    }
  }, {
    // prime2 (q)
    name: 'RSAPrivateKey.prime2',
    tagClass: asn1.Class.UNIVERSAL,
    type: asn1.Type.INTEGER,
    constructed: false,
    capture: {
      name: 'privateKeyPrime2',
      format: 'buffer'
    }
  }, {
    // exponent1 (d mod (p-1))
    name: 'RSAPrivateKey.exponent1',
    tagClass: asn1.Class.UNIVERSAL,
    type: asn1.Type.INTEGER,
    constructed: false,
    capture: {
      name: 'privateKeyExponent1',
      format: 'buffer'
    }
  }, {
    // exponent2 (d mod (q-1))
    name: 'RSAPrivateKey.exponent2',
    tagClass: asn1.Class.UNIVERSAL,
    type: asn1.Type.INTEGER,
    constructed: false,
    capture: {
      name: 'privateKeyExponent2',
      format: 'buffer'
    }
  }, {
    // coefficient ((inverse of q) mod p)
    name: 'RSAPrivateKey.coefficient',
    tagClass: asn1.Class.UNIVERSAL,
    type: asn1.Type.INTEGER,
    constructed: false,
    capture: {
      name: 'privateKeyCoefficient',
      format: 'buffer'
    }
  }]
};

// validator for an RSA public key
var rsaPublicKeyValidator = {
  // RSAPublicKey
  name: 'RSAPublicKey',
  tagClass: asn1.Class.UNIVERSAL,
  type: asn1.Type.SEQUENCE,
  constructed: true,
  value: [{
    // modulus (n)
    name: 'RSAPublicKey.modulus',
    tagClass: asn1.Class.UNIVERSAL,
    type: asn1.Type.INTEGER,
    constructed: false,
    capture: {
      name: 'publicKeyModulus',
      format: 'buffer'
    }
  }, {
    // publicExponent (e)
    name: 'RSAPublicKey.exponent',
    tagClass: asn1.Class.UNIVERSAL,
    type: asn1.Type.INTEGER,
    constructed: false,
    capture: {
      name: 'publicKeyExponent',
      format: 'buffer'
    }
  }]
};

// validator for an SubjectPublicKeyInfo structure
// Note: Currently only works with an RSA public key
var publicKeyValidator = forge.pki.rsa.publicKeyValidator = {
  name: 'SubjectPublicKeyInfo',
  tagClass: asn1.Class.UNIVERSAL,
  type: asn1.Type.SEQUENCE,
  constructed: true,
  capture: {
    name: 'subjectPublicKeyInfo',
    format: 'asn1'
  },
  value: [{
    name: 'SubjectPublicKeyInfo.AlgorithmIdentifier',
    tagClass: asn1.Class.UNIVERSAL,
    type: asn1.Type.SEQUENCE,
    constructed: true,
    value: [{
      name: 'AlgorithmIdentifier.algorithm',
      tagClass: asn1.Class.UNIVERSAL,
      type: asn1.Type.OID,
      constructed: false,
      capture: 'publicKeyOid'
    }]
  }, {
    // subjectPublicKey
    name: 'SubjectPublicKeyInfo.subjectPublicKey',
    tagClass: asn1.Class.UNIVERSAL,
    type: asn1.Type.BITSTRING,
    constructed: false,
    value: [{
      // RSAPublicKey
      name: 'SubjectPublicKeyInfo.subjectPublicKey.RSAPublicKey',
      tagClass: asn1.Class.UNIVERSAL,
      type: asn1.Type.SEQUENCE,
      constructed: true,
      optional: true,
      capture: {
        name: 'rsaPublicKey',
        format: 'asn1'
      }
    }]
  }]
};

/**
 * Creates an RSA key-pair generation state object. It is used to allow
 * key-generation to be performed in steps. It also allows for a UI to
 * display progress updates.
 *
 * @param bits the size for the private key in bits, defaults to 2048.
 * @param e the public exponent to use, defaults to 65537 (0x10001).
 * @param [options] the options to use.
 *          prng a custom crypto-secure pseudo-random number generator to use,
 *            that must define "getBytesSync".
 *          algorithm the algorithm to use (default: 'PRIMEINC').
 *
 * @return the state object to use to generate the key-pair.
 */
pki.rsa.createKeyPairGenerationState = function(bits, e, options) {
  // TODO: migrate step-based prime generation code to forge.prime

  // set default bits
  if(typeof(bits) === 'string') {
    bits = parseInt(bits, 10);
  }
  bits = bits || 2048;

  // create prng with api that matches BigInteger secure random
  options = options || {};
  var prng = options.prng || forge.random;
  var rng = {
    // x is an array to fill with bytes
    nextBytes: function(x) {
      var b = prng.getBytesSync(x.length);
      for(var i = 0; i < x.length; ++i) {
        x[i] = b.charCodeAt(i);
      }
    }
  };

  var algorithm = options.algorithm || 'PRIMEINC';

  // create PRIMEINC algorithm state
  var rval;
  if(algorithm === 'PRIMEINC') {
    rval = {
      algorithm: algorithm,
      state: 0,
      bits: bits,
      rng: rng,
      eInt: e || 65537,
      e: new BigInteger(null),
      p: null,
      q: null,
      qBits: bits >> 1,
      pBits: bits - (bits >> 1),
      pqState: 0,
      num: null,
      keys: null
    };
    rval.e.fromInt(rval.eInt);
  } else {
    throw new Error('Invalid key generation algorithm: ' + algorithm);
  }

  return rval;
};

/**
 * Attempts to runs the key-generation algorithm for at most n seconds
 * (approximately) using the given state. When key-generation has completed,
 * the keys will be stored in state.keys.
 *
 * To use this function to update a UI while generating a key or to prevent
 * causing browser lockups/warnings, set "n" to a value other than 0. A
 * simple pattern for generating a key and showing a progress indicator is:
 *
 * var state = pki.rsa.createKeyPairGenerationState(2048);
 * var step = function() {
 *   // step key-generation, run algorithm for 100 ms, repeat
 *   if(!forge.pki.rsa.stepKeyPairGenerationState(state, 100)) {
 *     setTimeout(step, 1);
 *   } else {
 *     // key-generation complete
 *     // TODO: turn off progress indicator here
 *     // TODO: use the generated key-pair in "state.keys"
 *   }
 * };
 * // TODO: turn on progress indicator here
 * setTimeout(step, 0);
 *
 * @param state the state to use.
 * @param n the maximum number of milliseconds to run the algorithm for, 0
 *          to run the algorithm to completion.
 *
 * @return true if the key-generation completed, false if not.
 */
pki.rsa.stepKeyPairGenerationState = function(state, n) {
  // set default algorithm if not set
  if(!('algorithm' in state)) {
    state.algorithm = 'PRIMEINC';
  }

  // TODO: migrate step-based prime generation code to forge.prime
  // TODO: abstract as PRIMEINC algorithm

  // do key generation (based on Tom Wu's rsa.js, see jsbn.js license)
  // with some minor optimizations and designed to run in steps

  // local state vars
  var THIRTY = new BigInteger(null);
  THIRTY.fromInt(30);
  var deltaIdx = 0;
  var op_or = function(x,y) { return x|y; };

  // keep stepping until time limit is reached or done
  var t1 = +new Date();
  var t2;
  var total = 0;
  while(state.keys === null && (n <= 0 || total < n)) {
    // generate p or q
    if(state.state === 0) {
      /* Note: All primes are of the form:

        30k+i, for i < 30 and gcd(30, i)=1, where there are 8 values for i

        When we generate a random number, we always align it at 30k + 1. Each
        time the number is determined not to be prime we add to get to the
        next 'i', eg: if the number was at 30k + 1 we add 6. */
      var bits = (state.p === null) ? state.pBits : state.qBits;
      var bits1 = bits - 1;

      // get a random number
      if(state.pqState === 0) {
        state.num = new BigInteger(bits, state.rng);
        // force MSB set
        if(!state.num.testBit(bits1)) {
          state.num.bitwiseTo(
            BigInteger.ONE.shiftLeft(bits1), op_or, state.num);
        }
        // align number on 30k+1 boundary
        state.num.dAddOffset(31 - state.num.mod(THIRTY).byteValue(), 0);
        deltaIdx = 0;

        ++state.pqState;
      } else if(state.pqState === 1) {
        // try to make the number a prime
        if(state.num.bitLength() > bits) {
          // overflow, try again
          state.pqState = 0;
          // do primality test
        } else if(state.num.isProbablePrime(
          _getMillerRabinTests(state.num.bitLength()))) {
          ++state.pqState;
        } else {
          // get next potential prime
          state.num.dAddOffset(GCD_30_DELTA[deltaIdx++ % 8], 0);
        }
      } else if(state.pqState === 2) {
        // ensure number is coprime with e
        state.pqState =
          (state.num.subtract(BigInteger.ONE).gcd(state.e)
          .compareTo(BigInteger.ONE) === 0) ? 3 : 0;
      } else if(state.pqState === 3) {
        // store p or q
        state.pqState = 0;
        if(state.p === null) {
          state.p = state.num;
        } else {
          state.q = state.num;
        }

        // advance state if both p and q are ready
        if(state.p !== null && state.q !== null) {
          ++state.state;
        }
        state.num = null;
      }
    } else if(state.state === 1) {
      // ensure p is larger than q (swap them if not)
      if(state.p.compareTo(state.q) < 0) {
        state.num = state.p;
        state.p = state.q;
        state.q = state.num;
      }
      ++state.state;
    } else if(state.state === 2) {
      // compute phi: (p - 1)(q - 1) (Euler's totient function)
      state.p1 = state.p.subtract(BigInteger.ONE);
      state.q1 = state.q.subtract(BigInteger.ONE);
      state.phi = state.p1.multiply(state.q1);
      ++state.state;
    } else if(state.state === 3) {
      // ensure e and phi are coprime
      if(state.phi.gcd(state.e).compareTo(BigInteger.ONE) === 0) {
        // phi and e are coprime, advance
        ++state.state;
      } else {
        // phi and e aren't coprime, so generate a new p and q
        state.p = null;
        state.q = null;
        state.state = 0;
      }
    } else if(state.state === 4) {
      // create n, ensure n is has the right number of bits
      state.n = state.p.multiply(state.q);

      // ensure n is right number of bits
      if(state.n.bitLength() === state.bits) {
        // success, advance
        ++state.state;
      } else {
        // failed, get new q
        state.q = null;
        state.state = 0;
      }
    } else if(state.state === 5) {
      // set keys
      var d = state.e.modInverse(state.phi);
      state.keys = {
        privateKey: pki.rsa.setPrivateKey(
          state.n, state.e, d, state.p, state.q,
          d.mod(state.p1), d.mod(state.q1),
          state.q.modInverse(state.p)),
        publicKey: pki.rsa.setPublicKey(state.n, state.e)
      };
    }

    // update timing
    t2 = +new Date();
    total += t2 - t1;
    t1 = t2;
  }

  return state.keys !== null;
};

/**
 * Generates an RSA public-private key pair in a single call.
 *
 * To generate a key-pair in steps (to allow for progress updates and to
 * prevent blocking or warnings in slow browsers) then use the key-pair
 * generation state functions.
 *
 * To generate a key-pair asynchronously (either through web-workers, if
 * available, or by breaking up the work on the main thread), pass a
 * callback function.
 *
 * @param [bits] the size for the private key in bits, defaults to 2048.
 * @param [e] the public exponent to use, defaults to 65537.
 * @param [options] options for key-pair generation, if given then 'bits'
 *          and 'e' must *not* be given:
 *          bits the size for the private key in bits, (default: 2048).
 *          e the public exponent to use, (default: 65537 (0x10001)).
 *          workerScript the worker script URL.
 *          workers the number of web workers (if supported) to use,
 *            (default: 2).
 *          workLoad the size of the work load, ie: number of possible prime
 *            numbers for each web worker to check per work assignment,
 *            (default: 100).
 *          e the public exponent to use, defaults to 65537.
 *          prng a custom crypto-secure pseudo-random number generator to use,
 *            that must define "getBytesSync".
 *          algorithm the algorithm to use (default: 'PRIMEINC').
 * @param [callback(err, keypair)] called once the operation completes.
 *
 * @return an object with privateKey and publicKey properties.
 */
pki.rsa.generateKeyPair = function(bits, e, options, callback) {
  // (bits), (options), (callback)
  if(arguments.length === 1) {
    if(typeof bits === 'object') {
      options = bits;
      bits = undefined;
    } else if(typeof bits === 'function') {
      callback = bits;
      bits = undefined;
    }
  } else if(arguments.length === 2) {
    // (bits, e), (bits, options), (bits, callback), (options, callback)
    if(typeof bits === 'number') {
      if(typeof e === 'function') {
        callback = e;
        e = undefined;
      } else if(typeof e !== 'number') {
        options = e;
        e = undefined;
      }
    } else {
      options = bits;
      callback = e;
      bits = undefined;
      e = undefined;
    }
  } else if(arguments.length === 3) {
    // (bits, e, options), (bits, e, callback), (bits, options, callback)
    if(typeof e === 'number') {
      if(typeof options === 'function') {
        callback = options;
        options = undefined;
      }
    } else {
      callback = options;
      options = e;
      e = undefined;
    }
  }
  options = options || {};
  if(bits === undefined) {
    bits = options.bits || 2048;
  }
  if(e === undefined) {
    e = options.e || 0x10001;
  }
  var state = pki.rsa.createKeyPairGenerationState(bits, e, options);
  if(!callback) {
    pki.rsa.stepKeyPairGenerationState(state, 0);
    return state.keys;
  }
  _generateKeyPair(state, options, callback);
};

/**
 * Sets an RSA public key from BigIntegers modulus and exponent.
 *
 * @param n the modulus.
 * @param e the exponent.
 *
 * @return the public key.
 */
pki.setRsaPublicKey = pki.rsa.setPublicKey = function(n, e) {
  var key = {
    n: n,
    e: e
  };

  /**
   * Encrypts the given data with this public key. Newer applications
   * should use the 'RSA-OAEP' decryption scheme, 'RSAES-PKCS1-V1_5' is for
   * legacy applications.
   *
   * @param data the byte string to encrypt.
   * @param scheme the encryption scheme to use:
   *          'RSAES-PKCS1-V1_5' (default),
   *          'RSA-OAEP',
   *          'RAW', 'NONE', or null to perform raw RSA encryption,
   *          an object with an 'encode' property set to a function
   *          with the signature 'function(data, key)' that returns
   *          a binary-encoded string representing the encoded data.
   * @param schemeOptions any scheme-specific options.
   *
   * @return the encrypted byte string.
   */
  key.encrypt = function(data, scheme, schemeOptions) {
    if(typeof scheme === 'string') {
      scheme = scheme.toUpperCase();
    } else if(scheme === undefined) {
      scheme = 'RSAES-PKCS1-V1_5';
    }

    if(scheme === 'RSAES-PKCS1-V1_5') {
      scheme = {
        encode: function(m, key) {
          return forge.pkcs1.encode_rsaes(key, m);
        }
      };
    } else if(scheme === 'RSA-OAEP' || scheme === 'RSAES-OAEP') {
      scheme = {
        encode: function(m, key) {
          return forge.pkcs1.encode_rsa_oaep(key, m, schemeOptions);
        }
      };
    } else if(scheme === 'NONE' || scheme === null) {
      scheme = { encode: function(e) { return e; } };
    } else if(typeof scheme === 'string') {
      throw new Error('Unsupported encryption scheme: "' + scheme + '".');
    }

    // do scheme-based encoding then rsa encryption
    var e = scheme.encode(data, key, true);
    return _rsaRawEncrypt(e, key, true);
  };

  /**
   * Verifies the given signature against the given digest.
   *
   * PKCS#1 supports multiple (currently two) signature schemes:
   * RSASSA-PKCS1-V1_5 and RSASSA-PSS.
   *
   * By default this implementation uses the "old scheme", i.e.
   * RSASSA-PKCS1-V1_5, in which case once RSA-decrypted, the
   * signature is an OCTET STRING that holds a DigestInfo.
   *
   * DigestInfo ::= SEQUENCE {
   *   digestAlgorithm DigestAlgorithmIdentifier,
   *   digest Digest
   * }
   * DigestAlgorithmIdentifier ::= AlgorithmIdentifier
   * Digest ::= OCTET STRING
   *
   * To perform PSS signature verification, provide an instance
   * of Forge PSS object as the scheme parameter.
   *
   * @param digest the message digest hash to compare against the signature,
   *          as a binary-encoded string.
   * @param signature the signature to verify, as a binary-encoded string.
   * @param scheme signature verification scheme to use:
   *          'RSASSA-PKCS1-V1_5' or undefined for RSASSA PKCS#1 v1.5,
   *          a Forge PSS object for RSASSA-PSS,
   *          'EME-PKCS1-v1_5' for PKCS #1 v1.5 block type 2 encoding,
   *          'NONE' or null for none, meaning raw RSA decryption will be
   *            used (which is unsafe if some external padding mechanism isn't
   *            used).
   *
   * @return true if the signature was verified, false if not.
   */
  key.verify = function(digest, signature, scheme) {
    if(typeof scheme === 'string') {
      scheme = scheme.toUpperCase();
    } else if(scheme === undefined) {
      scheme = 'RSASSA-PKCS1-V1_5';
    }

    if(scheme === 'RSASSA-PKCS1-V1_5') {
      scheme = {
        verify: function(digest, d) {
          // FIXME: digest to become a ByteBuffer, use ByteBuffer.equals?
          return forge.pkcs1.decode_rsassa(key, d).getBytes() === digest;
        }
      };
    } else if(scheme === 'EME-PKCS1-V1_5') {
      scheme = {
        verify: function(digest, d) {
          return forge.pkcs1.decode_eme_v1_5(key, d).getBytes() === digest;
        }
      };
    } else if(scheme === 'NONE' || scheme === null) {
      scheme = {
        verify: function(digest, d) {
          // FIXME: digest to become a ByteBuffer, use ByteBuffer.equals?
          return d.getBytes() === digest;
        }
      };
    } else if(typeof scheme === 'string') {
      throw new Error('Invalid signature scheme: ' + scheme);
    }

    // do rsa decryption w/o any decoding, then verify -- which does decoding
    // FIXME: d will change to a ByteBuffer
    var d = new ByteBuffer(_rsaRawDecrypt(signature, key, true), 'binary');
    return scheme.verify(digest, d, key.n.bitLength());
  };

  return key;
};

/**
 * Sets an RSA private key from BigIntegers modulus, exponent, primes,
 * prime exponents, and modular multiplicative inverse.
 *
 * @param n the modulus.
 * @param e the public exponent.
 * @param d the private exponent ((inverse of e) mod n).
 * @param p the first prime.
 * @param q the second prime.
 * @param dP exponent1 (d mod (p-1)).
 * @param dQ exponent2 (d mod (q-1)).
 * @param qInv ((inverse of q) mod p)
 *
 * @return the private key.
 */
pki.setRsaPrivateKey = pki.rsa.setPrivateKey = function(
  n, e, d, p, q, dP, dQ, qInv) {
  var key = {
    n: n,
    e: e,
    d: d,
    p: p,
    q: q,
    dP: dP,
    dQ: dQ,
    qInv: qInv
  };

  /**
   * Decrypts the given data with this private key. The decryption scheme
   * must match the one used to encrypt the data.
   *
   * @param data the byte string to decrypt.
   * @param scheme the decryption scheme to use:
   *          'RSAES-PKCS1-V1_5' (default),
   *          'RSA-OAEP',
   *          'RAW', 'NONE', or null to perform raw RSA decryption.
   * @param schemeOptions any scheme-specific options.
   *
   * @return the decrypted byte string.
   */
  key.decrypt = function(data, scheme, schemeOptions) {
    if(typeof scheme === 'string') {
      scheme = scheme.toUpperCase();
    } else if(scheme === undefined) {
      scheme = 'RSAES-PKCS1-V1_5';
    }

    // do rsa decryption w/o any decoding
    var d = _rsaRawDecrypt(data, key, false, false);

    if(scheme === 'RSAES-PKCS1-V1_5') {
      scheme = {decode: function(d, key) {
        return forge.pkcs1.decode_rsaes(key, d);
      }};
    } else if(scheme === 'RSA-OAEP' || scheme === 'RSAES-OAEP') {
      scheme = {
        decode: function(d, key) {
          return new ByteBuffer(
            forge.pkcs1.decode_rsa_oaep(key, d.bytes(), schemeOptions),
            'binary');
        }
      };
    } else if(scheme === 'NONE' || scheme === null) {
      scheme = {decode: function(d) {return d;}};
    } else {
      throw new Error('Unsupported encryption scheme: "' + scheme + '".');
    }

    // decode according to scheme
    return scheme.decode(new ByteBuffer(d, 'binary'), key, false).getBytes();
  };

  /**
   * Signs the given digest, producing a signature.
   *
   * PKCS#1 supports multiple (currently two) signature schemes:
   * RSASSA-PKCS1-V1_5 and RSASSA-PSS.
   *
   * By default this implementation uses the "old scheme", i.e.
   * RSASSA-PKCS1-V1_5. In order to generate a PSS signature, provide
   * an instance of Forge PSS object as the scheme parameter.
   *
   * @param md the message digest object with the hash to sign.
   * @param scheme the signature scheme to use:
   *          'RSASSA-PKCS1-V1_5' or undefined for RSASSA PKCS#1 v1.5,
   *          a Forge PSS object for RSASSA-PSS,
   *          'EME-PKCS1-v1_5' for PKCS #1 v1.5 block type 2 encoding,
   *          'NONE' or null for none, meaning raw RSA encryption will be
   *            used (which is unsafe if some external padding mechanism isn't
   *            used).
   *
   * @return the signature as a byte string.
   */
  key.sign = function(md, scheme) {
    /* Note: The internal implementation of RSA operations is being
      transitioned away from a PKCS#1 v1.5 hard-coded scheme. Some legacy
      code like the use of an encoding block type identifier 'bt' will
      eventually be removed. */

    if(typeof scheme === 'string') {
      scheme = scheme.toUpperCase();
    } else if(scheme === undefined) {
      // default
      scheme = 'RSASSA-PKCS1-V1_5';
    }

    if(scheme === 'RSASSA-PKCS1-V1_5') {
      scheme = {
        encode: function(d) {
          return forge.pkcs1.encode_rsassa(key, d);
        }
      };
    } else if(scheme === 'EME-PKCS1-V1_5') {
      scheme = {
        encode: function(d) {
          return forge.pkcs1.encode_eme_v1_5(key, d, 0x02).getBytes();
        }
      };
    } else if(scheme === 'NONE' || scheme === null) {
      scheme = {encode: function() {return md;}};
    } else if(typeof scheme === 'string') {
      throw new Error('Invalid signature scheme: ' + scheme);
    }

    // encode and then encrypt
    var d = scheme.encode(md, key.n.bitLength());
    return _rsaRawEncrypt(d, key, false);
  };

  return key;
};

/**
 * Wraps an RSAPrivateKey ASN.1 object in an ASN.1 PrivateKeyInfo object.
 *
 * @param rsaKey the ASN.1 RSAPrivateKey.
 *
 * @return the ASN.1 PrivateKeyInfo.
 */
pki.wrapRsaPrivateKey = function(rsaKey) {
  // PrivateKeyInfo
  return asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [
    // version (0)
    asn1.create(asn1.Class.UNIVERSAL, asn1.Type.INTEGER, false, 0),
    // privateKeyAlgorithm
    asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [
      asn1.create(
        asn1.Class.UNIVERSAL, asn1.Type.OID, false, pki.oids.rsaEncryption),
      asn1.create(asn1.Class.UNIVERSAL, asn1.Type.NULL, false, null)
    ]),
    // PrivateKey
    asn1.create(asn1.Class.UNIVERSAL, asn1.Type.OCTETSTRING, false,
      asn1.toDer(rsaKey))
    ]);
};

/**
 * Converts a private key from an ASN.1 object.
 *
 * @param obj the ASN.1 representation of a PrivateKeyInfo containing an
 *          RSAPrivateKey or an RSAPrivateKey.
 *
 * @return the private key.
 */
pki.privateKeyFromAsn1 = function(obj) {
  // get PrivateKeyInfo
  var capture = {};
  var errors = [];
  if(asn1.validate(obj, privateKeyValidator, capture, errors)) {
    obj = asn1.fromDer(capture.privateKey);
  }

  // get RSAPrivateKey
  capture = {};
  errors = [];
  if(!asn1.validate(obj, rsaPrivateKeyValidator, capture, errors)) {
    var error = new Error('Cannot read private key. ' +
      'ASN.1 object does not contain an RSAPrivateKey.');
    error.errors = errors;
    throw error;
  }

  // Note: Version is currently ignored.
  // capture.privateKeyVersion
  // FIXME: inefficient, get a BigInteger that uses byte strings
  var n, e, d, p, q, dP, dQ, qInv;
  n = capture.privateKeyModulus.toString('hex');
  e = capture.privateKeyPublicExponent.toString('hex');
  d = capture.privateKeyPrivateExponent.toString('hex');
  p = capture.privateKeyPrime1.toString('hex');
  q = capture.privateKeyPrime2.toString('hex');
  dP = capture.privateKeyExponent1.toString('hex');
  dQ = capture.privateKeyExponent2.toString('hex');
  qInv = capture.privateKeyCoefficient.toString('hex');

  // set private key
  return pki.setRsaPrivateKey(
    new BigInteger(n, 16),
    new BigInteger(e, 16),
    new BigInteger(d, 16),
    new BigInteger(p, 16),
    new BigInteger(q, 16),
    new BigInteger(dP, 16),
    new BigInteger(dQ, 16),
    new BigInteger(qInv, 16));
};

/**
 * Converts a private key to an ASN.1 RSAPrivateKey.
 *
 * @param key the private key.
 *
 * @return the ASN.1 representation of an RSAPrivateKey.
 */
pki.privateKeyToAsn1 = pki.privateKeyToRSAPrivateKey = function(key) {
  // RSAPrivateKey
  return asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [
    // version (0 = only 2 primes, 1 multiple primes)
    asn1.create(asn1.Class.UNIVERSAL, asn1.Type.INTEGER, false, 0),
    // modulus (n)
    asn1.create(asn1.Class.UNIVERSAL, asn1.Type.INTEGER, false,
      _bnToBuffer(key.n)),
    // publicExponent (e)
    asn1.create(asn1.Class.UNIVERSAL, asn1.Type.INTEGER, false,
      _bnToBuffer(key.e)),
    // privateExponent (d)
    asn1.create(asn1.Class.UNIVERSAL, asn1.Type.INTEGER, false,
      _bnToBuffer(key.d)),
    // privateKeyPrime1 (p)
    asn1.create(asn1.Class.UNIVERSAL, asn1.Type.INTEGER, false,
      _bnToBuffer(key.p)),
    // privateKeyPrime2 (q)
    asn1.create(asn1.Class.UNIVERSAL, asn1.Type.INTEGER, false,
      _bnToBuffer(key.q)),
    // privateKeyExponent1 (dP)
    asn1.create(asn1.Class.UNIVERSAL, asn1.Type.INTEGER, false,
      _bnToBuffer(key.dP)),
    // privateKeyExponent2 (dQ)
    asn1.create(asn1.Class.UNIVERSAL, asn1.Type.INTEGER, false,
      _bnToBuffer(key.dQ)),
    // coefficient (qInv)
    asn1.create(asn1.Class.UNIVERSAL, asn1.Type.INTEGER, false,
      _bnToBuffer(key.qInv))
  ]);
};

/**
 * Converts a public key from an ASN.1 SubjectPublicKeyInfo or RSAPublicKey.
 *
 * @param obj the asn1 representation of a SubjectPublicKeyInfo or RSAPublicKey.
 *
 * @return the public key.
 */
pki.publicKeyFromAsn1 = function(obj) {
  // get SubjectPublicKeyInfo
  var capture = {};
  var errors = [];
  if(asn1.validate(obj, publicKeyValidator, capture, errors)) {
    // check oid
    if(capture.publicKeyOid !== pki.oids.rsaEncryption) {
      var error = new Error('Cannot read public key. Unknown OID.');
      error.oid = capture.publicKeyOid;
      throw error;
    }
    obj = capture.rsaPublicKey;
  }

  // get RSA params
  errors = [];
  if(!asn1.validate(obj, rsaPublicKeyValidator, capture, errors)) {
    var error = new Error('Cannot read public key. ' +
      'ASN.1 object does not contain an RSAPublicKey.');
    error.errors = errors;
    throw error;
  }

  // FIXME: inefficient, do a cleaner conversion to BigInteger
  var n = capture.publicKeyModulus.toString('hex');
  var e = capture.publicKeyExponent.toString('hex');

  // set public key
  return pki.setRsaPublicKey(
    new BigInteger(n, 16),
    new BigInteger(e, 16));
};

/**
 * Converts a public key to an ASN.1 SubjectPublicKeyInfo.
 *
 * @param key the public key.
 *
 * @return the asn1 representation of a SubjectPublicKeyInfo.
 */
pki.publicKeyToAsn1 = pki.publicKeyToSubjectPublicKeyInfo = function(key) {
  // SubjectPublicKeyInfo
  return asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [
    // AlgorithmIdentifier
    asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [
      // algorithm
      asn1.create(asn1.Class.UNIVERSAL, asn1.Type.OID, false,
        pki.oids.rsaEncryption),
      // parameters (null)
      asn1.create(asn1.Class.UNIVERSAL, asn1.Type.NULL, false, null)
    ]),
    // subjectPublicKey
    asn1.create(asn1.Class.UNIVERSAL, asn1.Type.BITSTRING, false, [
      pki.publicKeyToRSAPublicKey(key)
    ])
  ]);
};

/**
 * Converts a public key to an ASN.1 RSAPublicKey.
 *
 * @param key the public key.
 *
 * @return the asn1 representation of a RSAPublicKey.
 */
pki.publicKeyToRSAPublicKey = function(key) {
  // RSAPublicKey
  return asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [
    // modulus (n)
    asn1.create(asn1.Class.UNIVERSAL, asn1.Type.INTEGER, false,
      _bnToBuffer(key.n)),
    // publicExponent (e)
    asn1.create(asn1.Class.UNIVERSAL, asn1.Type.INTEGER, false,
      _bnToBuffer(key.e))
  ]);
};

/**
 * NOTE: THIS METHOD IS DEPRECATED, use 'sign' on a private key object or
 * 'encrypt' on a public key object instead.
 *
 * Performs RSA encryption.
 *
 * @param m the message to encrypt as a byte string.
 * @param key the RSA key to use.
 * @param pub true for a public key operation, false for a private key.
 *
 * @return the encrypted bytes as a string.
 */
function _rsaRawEncrypt(m, key, pub) {
  var eb = new ByteBuffer(m, 'binary');

  // get the length of the modulus in bytes
  var k = Math.ceil(key.n.bitLength() / 8);

  // load encryption block as big integer 'x'
  // FIXME: hex conversion inefficient, get BigInteger w/byte strings
  var x = new BigInteger(eb.toHex(), 16);

  // do RSA encryption
  var y = _rsaModPow(x, key, pub);

  // convert y into the encrypted data byte string, if y is shorter in
  // bytes than k, then prepend zero bytes to fill up ed
  // FIXME: hex conversion inefficient, get BigInteger w/byte strings
  var yhex = y.toString(16);
  var ed = new ByteBuffer();
  var zeros = k - Math.ceil(yhex.length / 2);
  while(zeros > 0) {
    ed.putByte(0x00);
    --zeros;
  }
  ed.putBytes(forge.util.hexToBytes(yhex));
  return ed.getBytes();
}

/**
 * NOTE: THIS METHOD IS DEPRECATED, use 'decrypt' on a private key object or
 * 'verify' on a public key object instead.
 *
 * Performs RSA decryption.
 *
 * @param ed the encrypted data to decrypt in as a byte string.
 * @param key the RSA key to use.
 * @param pub true for a public key operation, false for private.
 *
 * @return the decrypted message as a byte string.
 */
function _rsaRawDecrypt(ed, key, pub) {
  // get the length of the modulus in bytes
  var k = Math.ceil(key.n.bitLength() / 8);

  // error if the length of the encrypted data ED is not k
  if(ed.length !== k) {
    var error = new Error('Encrypted message length is invalid.');
    error.length = ed.length;
    error.expected = k;
    throw error;
  }

  // convert encrypted data into a big integer
  // FIXME: hex conversion inefficient, get BigInteger w/byte strings
  var y = new BigInteger(new ByteBuffer(ed, 'binary').toString('hex'), 16);

  // y must be less than the modulus or it wasn't the result of
  // a previous mod operation (encryption) using that modulus
  if(y.compareTo(key.n) >= 0) {
    throw new Error('Encrypted message is invalid.');
  }

  // do RSA decryption
  var x = _rsaModPow(y, key, pub);

  // create the encryption block, if x is shorter in bytes than k, then
  // prepend zero bytes to fill up eb
  // FIXME: hex conversion inefficient, get BigInteger w/byte strings
  var xhex = x.toString(16);
  var eb = new ByteBuffer();
  var zeros = k - Math.ceil(xhex.length / 2);
  while(zeros > 0) {
    eb.putByte(0x00);
    --zeros;
  }
  eb.putBytes(forge.util.hexToBytes(xhex));

  // return message
  return eb.getBytes();
}

/**
 * Performs x^c mod n (RSA encryption or decryption operation).
 *
 * @param x the number to raise and mod.
 * @param key the key to use.
 * @param pub true if the key is public, false if private.
 *
 * @return the result of x^c mod n.
 */
function _rsaModPow(x, key, pub) {
  if(pub) {
    return x.modPow(key.e, key.n);
  }

  if(!key.p || !key.q) {
    // allow calculation without CRT params (slow).
    return x.modPow(key.d, key.n);
  }

  // pre-compute dP, dQ, and qInv if necessary
  if(!key.dP) {
    key.dP = key.d.mod(key.p.subtract(BigInteger.ONE));
  }
  if(!key.dQ) {
    key.dQ = key.d.mod(key.q.subtract(BigInteger.ONE));
  }
  if(!key.qInv) {
    key.qInv = key.q.modInverse(key.p);
  }

  /* Chinese remainder theorem (CRT) states:

    Suppose n1, n2, ..., nk are positive integers which are pairwise
    coprime (n1 and n2 have no common factors other than 1). For any
    integers x1, x2, ..., xk there exists an integer x solving the
    system of simultaneous congruences (where ~= means modularly
    congruent so a ~= b mod n means a mod n = b mod n):

    x ~= x1 mod n1
    x ~= x2 mod n2
    ...
    x ~= xk mod nk

    This system of congruences has a single simultaneous solution x
    between 0 and n - 1. Furthermore, each xk solution and x itself
    is congruent modulo the product n = n1*n2*...*nk.
    So x1 mod n = x2 mod n = xk mod n = x mod n.

    The single simultaneous solution x can be solved with the following
    equation:

    x = sum(xi*ri*si) mod n where ri = n/ni and si = ri^-1 mod ni.

    Where x is less than n, xi = x mod ni.

    For RSA we are only concerned with k = 2. The modulus n = pq, where
    p and q are coprime. The RSA decryption algorithm is:

    y = x^d mod n

    Given the above:

    x1 = x^d mod p
    r1 = n/p = q
    s1 = q^-1 mod p
    x2 = x^d mod q
    r2 = n/q = p
    s2 = p^-1 mod q

    So y = (x1r1s1 + x2r2s2) mod n
         = ((x^d mod p)q(q^-1 mod p) + (x^d mod q)p(p^-1 mod q)) mod n

    According to Fermat's Little Theorem, if the modulus P is prime,
    for any integer A not evenly divisible by P, A^(P-1) ~= 1 mod P.
    Since A is not divisible by P it follows that if:
    N ~= M mod (P - 1), then A^N mod P = A^M mod P. Therefore:

    A^N mod P = A^(M mod (P - 1)) mod P. (The latter takes less effort
    to calculate). In order to calculate x^d mod p more quickly the
    exponent d mod (p - 1) is stored in the RSA private key (the same
    is done for x^d mod q). These values are referred to as dP and dQ
    respectively. Therefore we now have:

    y = ((x^dP mod p)q(q^-1 mod p) + (x^dQ mod q)p(p^-1 mod q)) mod n

    Since we'll be reducing x^dP by modulo p (same for q) we can also
    reduce x by p (and q respectively) before hand. Therefore, let

    xp = ((x mod p)^dP mod p), and
    xq = ((x mod q)^dQ mod q), yielding:

    y = (xp*q*(q^-1 mod p) + xq*p*(p^-1 mod q)) mod n

    This can be further reduced to a simple algorithm that only
    requires 1 inverse (the q inverse is used) to be used and stored.
    The algorithm is called Garner's algorithm. If qInv is the
    inverse of q, we simply calculate:

    y = (qInv*(xp - xq) mod p) * q + xq

    However, there are two further complications. First, we need to
    ensure that xp > xq to prevent signed BigIntegers from being used
    so we add p until this is true (since we will be mod'ing with
    p anyway). Then, there is a known timing attack on algorithms
    using the CRT. To mitigate this risk, "cryptographic blinding"
    should be used. This requires simply generating a random number r between
    0 and n-1 and its inverse and multiplying x by r^e before calculating y
    and then multiplying y by r^-1 afterwards.
  */

  // cryptographic blinding
  var r;
  do {
    r = new BigInteger(
      forge.util.bytesToHex(forge.random.getBytes(key.n.bitLength() / 8)),
      16).mod(key.n);
  } while(r.equals(BigInteger.ZERO));
  x = x.multiply(r.modPow(key.e, key.n)).mod(key.n);

  // calculate xp and xq
  var xp = x.mod(key.p).modPow(key.dP, key.p);
  var xq = x.mod(key.q).modPow(key.dQ, key.q);

  // xp must be larger than xq to avoid signed bit usage
  while(xp.compareTo(xq) < 0) {
    xp = xp.add(key.p);
  }

  // do last step
  var y = xp.subtract(xq)
    .multiply(key.qInv).mod(key.p)
    .multiply(key.q).add(xq);

  // remove effect of random for cryptographic blinding
  y = y.multiply(r.modInverse(key.n)).mod(key.n);

  return y;
}

/**
 * Runs the key-generation algorithm asynchronously, either in the background
 * via Web Workers, or using the main thread and setImmediate.
 *
 * @param state the key-pair generation state.
 * @param [options] options for key-pair generation:
 *          workerScript the worker script URL.
 *          workers the number of web workers (if supported) to use,
 *            (default: 2, -1 to use estimated cores minus one).
 *          workLoad the size of the work load, ie: number of possible prime
 *            numbers for each web worker to check per work assignment,
 *            (default: 100).
 * @param callback(err, keypair) called once the operation completes.
 */
function _generateKeyPair(state, options, callback) {
  if(typeof options === 'function') {
    callback = options;
    options = {};
  }
  options = options || {};

  var opts = {
    algorithm: {
      name: options.algorithm || 'PRIMEINC',
      options: {
        workers: options.workers || 2,
        workLoad: options.workLoad || 100,
        workerScript: options.workerScript
      }
    }
  };
  if('prng' in options) {
    opts.prng = options.prng;
  }

  generate();

  function generate() {
    // find p and then q (done in series to simplify)
    getPrime(state.pBits, function(err, num) {
      if(err) {
        return callback(err);
      }
      state.p = num;
      if(state.q !== null) {
        return finish(err, state.q);
      }
      getPrime(state.qBits, finish);
    });
  }

  function getPrime(bits, callback) {
    forge.prime.generateProbablePrime(bits, opts, callback);
  }

  function finish(err, num) {
    if(err) {
      return callback(err);
    }

    // set q
    state.q = num;

    // ensure p is larger than q (swap them if not)
    if(state.p.compareTo(state.q) < 0) {
      var tmp = state.p;
      state.p = state.q;
      state.q = tmp;
    }

    // ensure p is coprime with e
    if(state.p.subtract(BigInteger.ONE).gcd(state.e)
      .compareTo(BigInteger.ONE) !== 0) {
      state.p = null;
      generate();
      return;
    }

    // ensure q is coprime with e
    if(state.q.subtract(BigInteger.ONE).gcd(state.e)
      .compareTo(BigInteger.ONE) !== 0) {
      state.q = null;
      getPrime(state.qBits, finish);
      return;
    }

    // compute phi: (p - 1)(q - 1) (Euler's totient function)
    state.p1 = state.p.subtract(BigInteger.ONE);
    state.q1 = state.q.subtract(BigInteger.ONE);
    state.phi = state.p1.multiply(state.q1);

    // ensure e and phi are coprime
    if(state.phi.gcd(state.e).compareTo(BigInteger.ONE) !== 0) {
      // phi and e aren't coprime, so generate a new p and q
      state.p = state.q = null;
      generate();
      return;
    }

    // create n, ensure n is has the right number of bits
    state.n = state.p.multiply(state.q);
    if(state.n.bitLength() !== state.bits) {
      // failed, get new q
      state.q = null;
      getPrime(state.qBits, finish);
      return;
    }

    // set keys
    var d = state.e.modInverse(state.phi);
    state.keys = {
      privateKey: pki.rsa.setPrivateKey(
        state.n, state.e, d, state.p, state.q,
        d.mod(state.p1), d.mod(state.q1),
        state.q.modInverse(state.p)),
      publicKey: pki.rsa.setPublicKey(state.n, state.e)
    };

    callback(null, state.keys);
  }
}

/**
 * Converts a positive BigInteger into 2's-complement big-endian bytes in
 * a ByteBuffer.
 *
 * @param b the big integer to convert.
 *
 * @return the ByteBuffer.
 */
function _bnToBuffer(b) {
  // prepend 0x00 if first byte >= 0x80
  var hex = b.toString(16);
  if(hex[0] >= '8') {
    hex = '00' + hex;
  }
  return new ByteBuffer(hex, 'hex');
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
function _getMillerRabinTests(bits) {
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
var name = 'rsa';
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
  './asn1',
  './jsbn',
  './oids',
  './pkcs1',
  './prime',
  './random',
  './util'
], function() {
  defineFunc.apply(null, Array.prototype.slice.call(arguments, 0));
});
})();
