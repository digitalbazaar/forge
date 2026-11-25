/**
 * Copyright (c) 2019 Digital Bazaar, Inc.
 */

var forge = require('./forge');
require('./asn1');
var asn1 = forge.asn1;

exports.privateKeyValidator = {
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
      capture: 'privateKeyOid'
    }]
  }, {
    // PrivateKey
    name: 'PrivateKeyInfo',
    tagClass: asn1.Class.UNIVERSAL,
    type: asn1.Type.OCTETSTRING,
    capture: 'privateKey'
  }]
};

exports.publicKeyInfoValidator = {
  name: 'SubjectPublicKeyInfo',
  tagClass: asn1.Class.UNIVERSAL,
  type: asn1.Type.SEQUENCE,
  constructed: true,
  captureAsn1: 'subjectPublicKeyInfo',
  value: [{
    name: 'SubjectPublicKeyInfo.AlgorithmIdentifier',
    tagClass: asn1.Class.UNIVERSAL,
    type: asn1.Type.SEQUENCE,
    constructed: true,
    value: [{
        name: 'AlgorithmIdentifier.algorithm',
        tagClass: asn1.Class.UNIVERSAL,
        type: asn1.Type.OID,
        capture: 'publicKeyOid'
      },
      {
        name: 'AlgorithmIdentifier.parameters',
        tagClass: asn1.Class.UNIVERSAL,
        optional: true,
        captureAsn1: 'parameters',
      }]
  }, {
    // subjectPublicKey
    name: 'SubjectPublicKeyInfo.subjectPublicKey',
    tagClass: asn1.Class.UNIVERSAL,
    type: asn1.Type.BITSTRING,
    constructed: false,
    captureAsn1: 'subjectPublicKey', // used by RSA
    captureBitStringValue: 'subjectPublicKeyRaw', // used by ECDSA and ED25519
  }]
};
