/**
 * Javascript implementation of ASN.1 validators for PKCS#7 v1.5.
 *
 * @author Dave Longley
 * @author Stefan Siegl
 *
 * Copyright (c) 2012-2015 Digital Bazaar, Inc.
 * Copyright (c) 2012 Stefan Siegl <stesie@brokenpipe.de>
 *
 * The ASN.1 representation of PKCS#7 is as follows
 * (see RFC #2315 for details, http://www.ietf.org/rfc/rfc2315.txt):
 *
 * A PKCS#7 message consists of a ContentInfo on root level, which may
 * contain any number of further ContentInfo nested into it.
 *
 * ContentInfo ::= SEQUENCE {
 *   contentType                ContentType,
 *   content               [0]  EXPLICIT ANY DEFINED BY contentType OPTIONAL
 * }
 *
 * ContentType ::= OBJECT IDENTIFIER
 *
 * EnvelopedData ::= SEQUENCE {
 *   version                    Version,
 *   recipientInfos             RecipientInfos,
 *   encryptedContentInfo       EncryptedContentInfo
 * }
 *
 * EncryptedData ::= SEQUENCE {
 *   version                    Version,
 *   encryptedContentInfo       EncryptedContentInfo
 * }
 *
 * id-signedData OBJECT IDENTIFIER ::= { iso(1) member-body(2)
 *   us(840) rsadsi(113549) pkcs(1) pkcs7(7) 2 }
 *
 * SignedData ::= SEQUENCE {
 *   version           INTEGER,
 *   digestAlgorithms  DigestAlgorithmIdentifiers,
 *   contentInfo       ContentInfo,
 *   certificates      [0] IMPLICIT Certificates OPTIONAL,
 *   crls              [1] IMPLICIT CertificateRevocationLists OPTIONAL,
 *   signerInfos       SignerInfos
 * }
 *
 * SignerInfos ::= SET OF SignerInfo
 *
 * SignerInfo ::= SEQUENCE {
 *   version                    Version,
 *   issuerAndSerialNumber      IssuerAndSerialNumber,
 *   digestAlgorithm            DigestAlgorithmIdentifier,
 *   authenticatedAttributes    [0] IMPLICIT Attributes OPTIONAL,
 *   digestEncryptionAlgorithm  DigestEncryptionAlgorithmIdentifier,
 *   encryptedDigest            EncryptedDigest,
 *   unauthenticatedAttributes  [1] IMPLICIT Attributes OPTIONAL
 * }
 *
 * EncryptedDigest ::= OCTET STRING
 *
 * Attributes ::= SET OF Attribute
 *
 * Attribute ::= SEQUENCE {
 *   attrType    OBJECT IDENTIFIER,
 *   attrValues  SET OF AttributeValue
 * }
 *
 * AttributeValue ::= ANY
 *
 * Version ::= INTEGER
 *
 * RecipientInfos ::= SET OF RecipientInfo
 *
 * EncryptedContentInfo ::= SEQUENCE {
 *   contentType                 ContentType,
 *   contentEncryptionAlgorithm  ContentEncryptionAlgorithmIdentifier,
 *   encryptedContent       [0]  IMPLICIT EncryptedContent OPTIONAL
 * }
 *
 * ContentEncryptionAlgorithmIdentifier ::= AlgorithmIdentifier
 *
 * The AlgorithmIdentifier contains an Object Identifier (OID) and parameters
 * for the algorithm, if any. In the case of AES and DES3, there is only one,
 * the IV.
 *
 * AlgorithmIdentifer ::= SEQUENCE {
 *    algorithm OBJECT IDENTIFIER,
 *    parameters ANY DEFINED BY algorithm OPTIONAL
 * }
 *
 * EncryptedContent ::= OCTET STRING
 *
 * RecipientInfo ::= SEQUENCE {
 *   version                     Version,
 *   issuerAndSerialNumber       IssuerAndSerialNumber,
 *   keyEncryptionAlgorithm      KeyEncryptionAlgorithmIdentifier,
 *   encryptedKey                EncryptedKey
 * }
 *
 * IssuerAndSerialNumber ::= SEQUENCE {
 *   issuer                      Name,
 *   serialNumber                CertificateSerialNumber
 * }
 *
 * CertificateSerialNumber ::= INTEGER
 *
 * KeyEncryptionAlgorithmIdentifier ::= AlgorithmIdentifier
 *
 * EncryptedKey ::= OCTET STRING
 */
// ASN.1 API
var asn1ct = require("./asn1ClassType");

// PKCS#7 API
var p7v = {};

module.exports = p7v;

var contentInfoValidator = {
  name: 'ContentInfo',
  tagClass: asn1ct.Class.UNIVERSAL,
  type: asn1ct.Type.SEQUENCE,
  constructed: true,
  value: [{
    name: 'ContentInfo.ContentType',
    tagClass: asn1ct.Class.UNIVERSAL,
    type: asn1ct.Type.OID,
    constructed: false,
    capture: 'contentType'
  }, {
    name: 'ContentInfo.content',
    tagClass: asn1ct.Class.CONTEXT_SPECIFIC,
    type: 0,
    constructed: true,
    optional: true,
    captureAsn1: 'content'
  }]
};
p7v.contentInfoValidator = contentInfoValidator;

var encryptedContentInfoValidator = {
  name: 'EncryptedContentInfo',
  tagClass: asn1ct.Class.UNIVERSAL,
  type: asn1ct.Type.SEQUENCE,
  constructed: true,
  value: [{
    name: 'EncryptedContentInfo.contentType',
    tagClass: asn1ct.Class.UNIVERSAL,
    type: asn1ct.Type.OID,
    constructed: false,
    capture: 'contentType'
  }, {
    name: 'EncryptedContentInfo.contentEncryptionAlgorithm',
    tagClass: asn1ct.Class.UNIVERSAL,
    type: asn1ct.Type.SEQUENCE,
    constructed: true,
    value: [{
      name: 'EncryptedContentInfo.contentEncryptionAlgorithm.algorithm',
      tagClass: asn1ct.Class.UNIVERSAL,
      type: asn1ct.Type.OID,
      constructed: false,
      capture: 'encAlgorithm'
    }, {
      name: 'EncryptedContentInfo.contentEncryptionAlgorithm.parameter',
      tagClass: asn1ct.Class.UNIVERSAL,
      captureAsn1: 'encParameter'
    }]
  }, {
    name: 'EncryptedContentInfo.encryptedContent',
    tagClass: asn1ct.Class.CONTEXT_SPECIFIC,
    type: 0,
    /* The PKCS#7 structure output by OpenSSL somewhat differs from what
     * other implementations do generate.
     *
     * OpenSSL generates a structure like this:
     * SEQUENCE {
     *    ...
     *    [0]
     *       26 DA 67 D2 17 9C 45 3C B1 2A A8 59 2F 29 33 38
     *       C3 C3 DF 86 71 74 7A 19 9F 40 D0 29 BE 85 90 45
     *       ...
     * }
     *
     * Whereas other implementations (and this PKCS#7 module) generate:
     * SEQUENCE {
     *    ...
     *    [0] {
     *       OCTET STRING
     *          26 DA 67 D2 17 9C 45 3C B1 2A A8 59 2F 29 33 38
     *          C3 C3 DF 86 71 74 7A 19 9F 40 D0 29 BE 85 90 45
     *          ...
     *    }
     * }
     *
     * In order to support both, we just capture the context specific
     * field here.  The OCTET STRING bit is removed below.
     */
    capture: 'encryptedContent',
    captureAsn1: 'encryptedContentAsn1'
  }]
};

p7v.envelopedDataValidator = {
  name: 'EnvelopedData',
  tagClass: asn1ct.Class.UNIVERSAL,
  type: asn1ct.Type.SEQUENCE,
  constructed: true,
  value: [{
    name: 'EnvelopedData.Version',
    tagClass: asn1ct.Class.UNIVERSAL,
    type: asn1ct.Type.INTEGER,
    constructed: false,
    capture: 'version'
  }, {
    name: 'EnvelopedData.RecipientInfos',
    tagClass: asn1ct.Class.UNIVERSAL,
    type: asn1ct.Type.SET,
    constructed: true,
    captureAsn1: 'recipientInfos'
  }].concat(encryptedContentInfoValidator)
};

p7v.encryptedDataValidator = {
  name: 'EncryptedData',
  tagClass: asn1ct.Class.UNIVERSAL,
  type: asn1ct.Type.SEQUENCE,
  constructed: true,
  value: [{
    name: 'EncryptedData.Version',
    tagClass: asn1ct.Class.UNIVERSAL,
    type: asn1ct.Type.INTEGER,
    constructed: false,
    capture: 'version'
  }].concat(encryptedContentInfoValidator)
};

var signerValidator = {
  name: 'SignerInfo',
  tagClass: asn1ct.Class.UNIVERSAL,
  type: asn1ct.Type.SEQUENCE,
  constructed: true,
  value: [{
    name: 'SignerInfo.version',
    tagClass: asn1ct.Class.UNIVERSAL,
    type: asn1ct.Type.INTEGER,
    constructed: false
  }, {
    name: 'SignerInfo.issuerAndSerialNumber',
    tagClass: asn1ct.Class.UNIVERSAL,
    type: asn1ct.Type.SEQUENCE,
    constructed: true,
    value: [{
      name: 'SignerInfo.issuerAndSerialNumber.issuer',
      tagClass: asn1ct.Class.UNIVERSAL,
      type: asn1ct.Type.SEQUENCE,
      constructed: true,
      captureAsn1: 'issuer'
    }, {
      name: 'SignerInfo.issuerAndSerialNumber.serialNumber',
      tagClass: asn1ct.Class.UNIVERSAL,
      type: asn1ct.Type.INTEGER,
      constructed: false,
      capture: 'serial'
    }]
  }, {
    name: 'SignerInfo.digestAlgorithm',
    tagClass: asn1ct.Class.UNIVERSAL,
    type: asn1ct.Type.SEQUENCE,
    constructed: true,
    value: [{
      name: 'SignerInfo.digestAlgorithm.algorithm',
      tagClass: asn1ct.Class.UNIVERSAL,
      type: asn1ct.Type.OID,
      constructed: false,
      capture: 'digestAlgorithm'
    }, {
      name: 'SignerInfo.digestAlgorithm.parameter',
      tagClass: asn1ct.Class.UNIVERSAL,
      constructed: false,
      captureAsn1: 'digestParameter',
      optional: true
    }]
  }, {
    name: 'SignerInfo.authenticatedAttributes',
    tagClass: asn1ct.Class.CONTEXT_SPECIFIC,
    type: 0,
    constructed: true,
    optional: true,
    capture: 'authenticatedAttributes'
  }, {
    name: 'SignerInfo.digestEncryptionAlgorithm',
    tagClass: asn1ct.Class.UNIVERSAL,
    type: asn1ct.Type.SEQUENCE,
    constructed: true,
    capture: 'signatureAlgorithm'
  }, {
    name: 'SignerInfo.encryptedDigest',
    tagClass: asn1ct.Class.UNIVERSAL,
    type: asn1ct.Type.OCTETSTRING,
    constructed: false,
    capture: 'signature'
  }, {
    name: 'SignerInfo.unauthenticatedAttributes',
    tagClass: asn1ct.Class.CONTEXT_SPECIFIC,
    type: 1,
    constructed: true,
    optional: true,
    capture: 'unauthenticatedAttributes'
  }]
};

p7v.signedDataValidator = {
  name: 'SignedData',
  tagClass: asn1ct.Class.UNIVERSAL,
  type: asn1ct.Type.SEQUENCE,
  constructed: true,
  value: [{
    name: 'SignedData.Version',
    tagClass: asn1ct.Class.UNIVERSAL,
    type: asn1ct.Type.INTEGER,
    constructed: false,
    capture: 'version'
  }, {
    name: 'SignedData.DigestAlgorithms',
    tagClass: asn1ct.Class.UNIVERSAL,
    type: asn1ct.Type.SET,
    constructed: true,
    captureAsn1: 'digestAlgorithms'
  },
  contentInfoValidator,
  {
    name: 'SignedData.Certificates',
    tagClass: asn1ct.Class.CONTEXT_SPECIFIC,
    type: 0,
    optional: true,
    captureAsn1: 'certificates'
  }, {
    name: 'SignedData.CertificateRevocationLists',
    tagClass: asn1ct.Class.CONTEXT_SPECIFIC,
    type: 1,
    optional: true,
    captureAsn1: 'crls'
  }, {
    name: 'SignedData.SignerInfos',
    tagClass: asn1ct.Class.UNIVERSAL,
    type: asn1ct.Type.SET,
    capture: 'signerInfos',
    optional: true,
    value: [signerValidator]
  }]
};

p7v.recipientInfoValidator = {
  name: 'RecipientInfo',
  tagClass: asn1ct.Class.UNIVERSAL,
  type: asn1ct.Type.SEQUENCE,
  constructed: true,
  value: [{
    name: 'RecipientInfo.version',
    tagClass: asn1ct.Class.UNIVERSAL,
    type: asn1ct.Type.INTEGER,
    constructed: false,
    capture: 'version'
  }, {
    name: 'RecipientInfo.issuerAndSerial',
    tagClass: asn1ct.Class.UNIVERSAL,
    type: asn1ct.Type.SEQUENCE,
    constructed: true,
    value: [{
      name: 'RecipientInfo.issuerAndSerial.issuer',
      tagClass: asn1ct.Class.UNIVERSAL,
      type: asn1ct.Type.SEQUENCE,
      constructed: true,
      captureAsn1: 'issuer'
    }, {
      name: 'RecipientInfo.issuerAndSerial.serialNumber',
      tagClass: asn1ct.Class.UNIVERSAL,
      type: asn1ct.Type.INTEGER,
      constructed: false,
      capture: 'serial'
    }]
  }, {
    name: 'RecipientInfo.keyEncryptionAlgorithm',
    tagClass: asn1ct.Class.UNIVERSAL,
    type: asn1ct.Type.SEQUENCE,
    constructed: true,
    value: [{
      name: 'RecipientInfo.keyEncryptionAlgorithm.algorithm',
      tagClass: asn1ct.Class.UNIVERSAL,
      type: asn1ct.Type.OID,
      constructed: false,
      capture: 'encAlgorithm'
    }, {
      name: 'RecipientInfo.keyEncryptionAlgorithm.parameter',
      tagClass: asn1ct.Class.UNIVERSAL,
      constructed: false,
      captureAsn1: 'encParameter'
    }]
  }, {
    name: 'RecipientInfo.encryptedKey',
    tagClass: asn1ct.Class.UNIVERSAL,
    type: asn1ct.Type.OCTETSTRING,
    constructed: false,
    capture: 'encKey'
  }]
};
