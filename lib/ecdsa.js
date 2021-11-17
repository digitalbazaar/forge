/**
 * JavaScript implementation of ECDSA.
 *
 * Copyright (c) 2021 HAMANO Tsukasa <hamano@osstech.co.jp>
 *
 * This implementation is based on the elliptic
 *
 * https://github.com/indutny/elliptic/
 */
var forge = require('./forge');
require('./asn1');
require('./jsbn');
require('./random');
require('./sha512');
var util = require('./util');
var elliptic = require('elliptic');
var asn1Validator = require('./asn1-validator');
var publicKeyInfoValidator = asn1Validator.publicKeyInfoValidator;
var privateKeyValidator = asn1Validator.privateKeyValidator;
var asn1 = forge.asn1;

if(typeof BigInteger === 'undefined') {
  var BigInteger = forge.jsbn.BigInteger;
}

var ByteBuffer = util.ByteBuffer;
var NativeBuffer = typeof Buffer === 'undefined' ? Uint8Array : Buffer;

forge.pki = forge.pki || {};
module.exports = forge.pki.ecdsa = forge.ecdsa = forge.ecdsa || {};
var ecdsa = forge.ecdsa;

ecdsa.constants = {};

/*
 * Supported namedCurve listed here:
 * https://github.com/indutny/elliptic/blob/master/lib/elliptic/curves.js
 */
ecdsa.supportedCueves = [
  'p192',     // secp192r1, prime192v1
  'p256',     // secp256r1, prime256v1
  'p224',     // secp224r1,
  'p384',     // secp384r1
  'p521',     // secp521r1
  'secp256k1',// secp256k1
];

/*
 * RCF5915: Elliptic Curve Private Key Format
 * https://datatracker.ietf.org/doc/html/rfc5915
 *
 * ECPrivateKey ::= SEQUENCE {
 *   version        INTEGER { ecPrivkeyVer1(1) } (ecPrivkeyVer1),
 *   privateKey     OCTET STRING,
 *   parameters [0] ECParameters {{ NamedCurve }} OPTIONAL,
 *   publicKey  [1] BIT STRING OPTIONAL
 * }
 */
var ecPrivateKeyValidator = {
  name: 'ECPrivateKey',
  tagClass: asn1.Class.UNIVERSAL,
  type: asn1.Type.SEQUENCE,
  constructed: true,
  value: [{
    name: 'ECPrivateKey.version',
    tagClass: asn1.Class.UNIVERSAL,
    type: asn1.Type.INTEGER,
    capture: 'version',
  }, {
    name: 'ECPrivateKey.privateKey',
    tagClass: asn1.Class.UNIVERSAL,
    type: asn1.Type.OCTETSTRING,
    capture: 'privateKey',
  }, {
    tagClass: asn1.Class.CONTEXT_SPECIFIC,
    type: 0x0,
    optional: true,
    value: [{
      name: 'ECPrivateKey.parameters',
      tagClass: asn1.Class.UNIVERSAL,
      type: asn1.Type.OID,
      captureAsn1: 'parameters',
    }],
  }, {
    tagClass: asn1.Class.CONTEXT_SPECIFIC,
    type: 0x1,
    optional: true,
    value: [{
      name: 'ECPrivateKey.publicKey',
      type: asn1.Type.BITSTRING,
      captureAsn1: 'publicKey',
    }],
  }]
};

var ecSpecifiedCurveValidator = {
  name: 'SpecifiedCurve',
  tagClass: asn1.Class.UNIVERSAL,
  type: asn1.Type.SEQUENCE,
  constructed: true,
  value: [{
    name: 'SpecifiedCurveVersion',
    tagClass: asn1.Class.UNIVERSAL,
    type: asn1.Type.INTEGER,
    capture: 'version',
  }, {
    name: 'SpecifiedCurve.FieldID',
    tagClass: asn1.Class.UNIVERSAL,
    type: asn1.Type.SEQUENCE,
    constructed: true,
    value: [{
      name: 'SpecifiedCurve.FieldID.fieldType',
      tagClass: asn1.Class.UNIVERSAL,
      type: asn1.Type.OID,
      capture: 'fieldType',
    }, {
      name: 'SpecifiedCurve.FieldID.prime',
      tagClass: asn1.Class.UNIVERSAL,
      type: asn1.Type.INTEGER,
      capture: 'p',
    }]
  }, {
    name: 'SpecifiedCurve.Curve',
    tagClass: asn1.Class.UNIVERSAL,
    type: asn1.Type.SEQUENCE,
    constructed: true,
    value: [{
      name: 'SpecifiedCurve.Curve.a',
      tagClass: asn1.Class.UNIVERSAL,
      type: asn1.Type.OCTETSTRING,
      capture: 'a',
    }, {
      name: 'SpecifiedCurve.Curve.b',
      tagClass: asn1.Class.UNIVERSAL,
      type: asn1.Type.OCTETSTRING,
      capture: 'b',
    }]
  }, {
    name: 'SpecifiedCurve.Generator',
    tagClass: asn1.Class.UNIVERSAL,
    type: asn1.Type.OCTETSTRING,
    capture: 'g',
  }, {
    name: 'SpecifiedCurve.Order',
    tagClass: asn1.Class.UNIVERSAL,
    type: asn1.Type.INTEGER,
    capture: 'n',
  }, {
    name: 'SpecifiedCurve.Confactor',
    tagClass: asn1.Class.UNIVERSAL,
    type: asn1.Type.INTEGER,
    capture: 'c',
    optional: true
  }]
};

ecdsa.generateKeyPair = function(options) {
  options = options || {};
  var curveName = options.name || 'p256';
  var seed = options.seed;
  var errors = [];

  if (!(ecdsa.supportedCueves.includes(curveName))) {
    var error = new Error('unsupported curveName: ' + curveName);
    error.errors = errors;
    throw error;
  }
  var curve = elliptic.curves[curveName];
  var ec = new elliptic.ec(curve);
  ec.curveName = curveName;
  var kp = ec.genKeyPair({
    entropy: seed,
  });
  var privateKey = kp.getPrivate();
  var publicKey = kp.getPublic();
  return {
    publicKey: new ecdsa.ECPublicKey(kp.ec, publicKey),
    privateKey: new ecdsa.ECPrivateKey(kp.ec, privateKey)
  };
};

/**
 * Converts a ECPrivateKey to an ASN.1 representation.
 *
 * @param key the ECPrivateKey.
 *
 * @return the ASN.1 representation of an ECPrivateKey.
 */
ecdsa.privateKeyToAsn1 = function(key, options) {
  return key.toAsn1(options);
};

ecdsa.ECPublicKey = ECPublicKey = function(ec, publicKey) {
  this._ec = ec;
  this._publicKey = publicKey;
};

/**
 * Converts a public key from a RFC8410 ASN.1 encoding.
 *
 * @param obj - The asn1 representation of a public key.
 *
 * @return {ECPublicKey} - ECPublicKey object.
 */
ECPublicKey.fromAsn1 = function(obj) {
  var capture = {};
  var errors = [];
  if(!forge.asn1.validate(obj, publicKeyInfoValidator, capture, errors)) {
    var error = new Error('Cannot read PublicKeyInfo ASN.1 object.');
    error.errors = errors;
    throw error;
  }

  var publicKey = capture.subjectPublicKeyRaw;
  var params = capture.parameters;
  var curve;
  var curveName;
  if(params && params.type === forge.asn1.Type.OID) {
    var oid = forge.asn1.derToOid(params.value);
    curveName = forge.oids[oid];
    if(!ecdsa.supportedCueves.includes(curveName)) {
      var error = new Error('Unsupported curveName: ' + curveName);
      error.errors = errors;
      throw error;
    }
    curve = elliptic.curves[curveName];
  } else if(params && params.type === forge.asn1.Type.SEQUENCE) {
    var capture = {};
    if(!forge.asn1.validate(params, ecSpecifiedCurveValidator, capture, errors)) {
      var error = new Error('Cannot read specified curve ASN.1 object.');
      error.errors = errors;
      throw error;
    }
    var options = {
      p: util.bytesToHex(capture.p),
      a: util.bytesToHex(capture.a),
      b: util.bytesToHex(capture.b),
      n: util.bytesToHex(capture.n),
    };
    var _curve = new elliptic.curve.short(options);
    var g = _curve.decodePoint(util.bytesToHex(capture.g), 'hex');
    curve = {
      curve: _curve,
      n: _curve.n,
      g: g
    };
  } else {
    var error = new Error('no ECParameters');
    error.errors = errors;
    throw error;
  }
  var ec = new elliptic.ec({curve: curve});
  ec.curveName = curveName;
  var kp = ec.keyFromPublic(publicKey);
  return new ECPublicKey(ec, kp.getPublic());
};

ECPublicKey.prototype.verify = function(msg, signature) {
    var hexMsg = util.bytesToHex(msg);
    var hexSignature = util.bytesToHex(signature);
    return this._ec.verify(hexMsg, hexSignature, this._publicKey, 'hex');
};

ECPublicKey.prototype.toString = function() {
  return this._publicKey.encode('hex');
};

ECPublicKey.prototype.getBytes = function() {
  return String.fromCharCode.apply(null, this._publicKey.encode());
};

ECPublicKey.prototype.toAsn1 = function(options) {
  var curveOID = forge.oids[this._ec.curveName];
  if (!curveOID) {
    var error = new Error('unsupported namedCurve or specifiedCurve.');
      error.errors = errors;
      throw error;
  }

  var obj = asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, []);
  var aid = asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [
    asn1.create(asn1.Class.UNIVERSAL, asn1.Type.OID, false,
                asn1.oidToDer(forge.oids['ecPublicKey']).getBytes()),
    asn1.create(asn1.Class.UNIVERSAL, asn1.Type.OID, false,
                asn1.oidToDer(curveOID).getBytes())]);
  obj.value.push(aid);
  obj.value.push(
    asn1.create(asn1.Class.UNIVERSAL, asn1.Type.BITSTRING, false,
                "\0" + this.getBytes()));
  return obj;
};

ECPublicKey.prototype.toDer = function() {
  return asn1.toDer(this.toAsn1()).getBytes();
};

ECPublicKey.prototype.toPem = function() {
  return '-----BEGIN PUBLIC KEY-----\n' +
    util.encode64(this.toDer(), 64) +
    '\n-----END PUBLIC KEY-----\n';
};


ecdsa.ECPrivateKey = ECPrivateKey = function(ec, privateKey) {
  this._ec = ec;
  this._privateKey = privateKey;
};

/**
 * Converts a private key from a RFC5915 ASN.1 Object.
 *
 * @param obj - The asn1 representation of a private key.
 *
 * @returns {Object} obj - The ASN.1 key object.
 * @returns {ECPrivateKey} ECPrivateKey object.
 */
ECPrivateKey.fromAsn1 = function(obj) {
  var capture = {};
  var errors = [];
  var valid = forge.asn1.validate(obj, ecPrivateKeyValidator, capture, errors);
  if(!valid) {
    var error = new Error('Invalid ECPrivateKey object.');
    error.errors = errors;
    throw error;
  }
  var params;
  if (!capture.parameters) {
    var error = new Error('no ECPrivateKey.parameters.');
    error.errors = errors;
    throw error;
  }
  var oid = asn1.derToOid(capture.parameters.value)
  var curveName = forge.oids[oid];
  if (!ecdsa.supportedCueves.includes(curveName)) {
    var error = new Error('unsupported curveName: ' + curveName);
    error.errors = errors;
    throw error;
  }
  curve = elliptic.curves[curveName];
  var ec = new elliptic.ec({curve: curve});
  ec.curveName = curveName;
  var kp = ec.keyFromPrivate(util.bytesToHex(capture.privateKey));
  return new ECPrivateKey(ec, kp.getPrivate());
};

ECPrivateKey.prototype.sign = function(msg) {
  var hexMsg = util.bytesToHex(msg);
  var signature = this._ec.sign(hexMsg, this._privateKey);
  return String.fromCharCode.apply(null, signature.toDER());
};

ECPrivateKey.prototype.toString = function() {
  return this._privateKey.toString('hex');
};

ECPrivateKey.prototype.getBytes = function() {
  return String.fromCharCode.apply(null, this._privateKey.toArray());
};

ECPrivateKey.prototype.toAsn1 = function(options) {
  var curveOID = forge.oids[this._ec.curveName];
  if (!curveOID) {
    var error = new Error('unsupported namedCurve');
      error.errors = errors;
      throw error;
  }
  return asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [
    asn1.create(asn1.Class.UNIVERSAL,
                asn1.Type.INTEGER, false,
                asn1.integerToDer(1).getBytes()),
    asn1.create(asn1.Class.UNIVERSAL, asn1.Type.OCTETSTRING, false,
                this.getBytes()),
    asn1.create(asn1.Class.CONTEXT_SPECIFIC, 0x0, true, [
      asn1.create(asn1.Class.UNIVERSAL, asn1.Type.OID, false,
                  asn1.oidToDer(curveOID).getBytes())
    ]),
  ]);
};

ECPrivateKey.prototype.toDer = function(options) {
  return asn1.toDer(this.toAsn1(options)).getBytes();
};

ECPrivateKey.prototype.toPem = function(options) {
  return '-----BEGIN EC PRIVATE KEY-----\n' +
    util.encode64(this.toDer(options), 64) +
    '\n-----END EC PRIVATE KEY-----\n';
};
