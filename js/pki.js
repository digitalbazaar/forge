/**
 * Javascript implementation of a basic Public Key Infrastructure, including
 * support for RSA public and private keys.
 *
 * @author Dave Longley
 * @author Stefan Siegl <stesie@brokenpipe.de>
 *
 * Copyright (c) 2010-2013 Digital Bazaar, Inc.
 * Copyright (c) 2012 Stefan Siegl <stesie@brokenpipe.de>
 *
 * The ASN.1 representation of an X.509v3 certificate is as follows
 * (see RFC 2459):
 *
 * Certificate ::= SEQUENCE {
 *   tbsCertificate       TBSCertificate,
 *   signatureAlgorithm   AlgorithmIdentifier,
 *   signatureValue       BIT STRING
 * }
 *
 * TBSCertificate ::= SEQUENCE {
 *   version         [0]  EXPLICIT Version DEFAULT v1,
 *   serialNumber         CertificateSerialNumber,
 *   signature            AlgorithmIdentifier,
 *   issuer               Name,
 *   validity             Validity,
 *   subject              Name,
 *   subjectPublicKeyInfo SubjectPublicKeyInfo,
 *   issuerUniqueID  [1]  IMPLICIT UniqueIdentifier OPTIONAL,
 *                        -- If present, version shall be v2 or v3
 *   subjectUniqueID [2]  IMPLICIT UniqueIdentifier OPTIONAL,
 *                        -- If present, version shall be v2 or v3
 *   extensions      [3]  EXPLICIT Extensions OPTIONAL
 *                        -- If present, version shall be v3
 * }
 *
 * Version ::= INTEGER  { v1(0), v2(1), v3(2) }
 *
 * CertificateSerialNumber ::= INTEGER
 *
 * Name ::= CHOICE {
 *   // only one possible choice for now
 *   RDNSequence
 * }
 *
 * RDNSequence ::= SEQUENCE OF RelativeDistinguishedName
 *
 * RelativeDistinguishedName ::= SET OF AttributeTypeAndValue
 *
 * AttributeTypeAndValue ::= SEQUENCE {
 *   type     AttributeType,
 *   value    AttributeValue
 * }
 * AttributeType ::= OBJECT IDENTIFIER
 * AttributeValue ::= ANY DEFINED BY AttributeType
 *
 * Validity ::= SEQUENCE {
 *   notBefore      Time,
 *   notAfter       Time
 * }
 *
 * Time ::= CHOICE {
 *   utcTime        UTCTime,
 *   generalTime    GeneralizedTime
 * }
 *
 * UniqueIdentifier ::= BIT STRING
 *
 * SubjectPublicKeyInfo ::= SEQUENCE {
 *   algorithm            AlgorithmIdentifier,
 *   subjectPublicKey     BIT STRING
 * }
 *
 * Extensions ::= SEQUENCE SIZE (1..MAX) OF Extension
 *
 * Extension ::= SEQUENCE {
 *   extnID      OBJECT IDENTIFIER,
 *   critical    BOOLEAN DEFAULT FALSE,
 *   extnValue   OCTET STRING
 * }
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
 * EncryptedPrivateKeyInfo ::= SEQUENCE {
 *   encryptionAlgorithm  EncryptionAlgorithmIdentifier,
 *   encryptedData        EncryptedData
 * }
 *
 * EncryptionAlgorithmIdentifier ::= AlgorithmIdentifier
 * EncryptedData ::= OCTET STRING
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
 *
 * An EncryptedPrivateKeyInfo:
 *
 * EncryptedPrivateKeyInfo ::= SEQUENCE {
 *   encryptionAlgorithm  EncryptionAlgorithmIdentifier,
 *   encryptedData        EncryptedData }
 *
 * EncryptionAlgorithmIdentifier ::= AlgorithmIdentifier
 *
 * EncryptedData ::= OCTET STRING
 *
 * RSASSA-PSS signatures are described in RFC 3447 and RFC 4055.
 *
 * PKCS#10 v1.7 describes certificate signing requests:
 *
 * CertificationRequestInfo:
 *
 * CertificationRequestInfo ::= SEQUENCE {
 *   version       INTEGER { v1(0) } (v1,...),
 *   subject       Name,
 *   subjectPKInfo SubjectPublicKeyInfo{{ PKInfoAlgorithms }},
 *   attributes    [0] Attributes{{ CRIAttributes }}
 * }
 *
 * Attributes { ATTRIBUTE:IOSet } ::= SET OF Attribute{{ IOSet }}
 *
 * CRIAttributes  ATTRIBUTE  ::= {
 *   ... -- add any locally defined attributes here -- }
 *
 * Attribute { ATTRIBUTE:IOSet } ::= SEQUENCE {
 *   type   ATTRIBUTE.&id({IOSet}),
 *   values SET SIZE(1..MAX) OF ATTRIBUTE.&Type({IOSet}{@type})
 * }
 *
 * CertificationRequest ::= SEQUENCE {
 *   certificationRequestInfo CertificationRequestInfo,
 *   signatureAlgorithm AlgorithmIdentifier{{ SignatureAlgorithms }},
 *   signature          BIT STRING
 * }
 */
(function() {
/* ########## Begin module implementation ########## */
function initModule(forge) {

if(typeof BigInteger === 'undefined') {
  BigInteger = forge.jsbn.BigInteger;
}

// shortcut for asn.1 API
var asn1 = forge.asn1;

/* Public Key Infrastructure (PKI) implementation. */
var pki = forge.pki = forge.pki || {};
var oids = pki.oids;

pki.pbe = {};

// short name OID mappings
var _shortNames = {};
_shortNames['CN'] = oids['commonName'];
_shortNames['commonName'] = 'CN';
_shortNames['C'] = oids['countryName'];
_shortNames['countryName'] = 'C';
_shortNames['L'] = oids['localityName'];
_shortNames['localityName'] = 'L';
_shortNames['ST'] = oids['stateOrProvinceName'];
_shortNames['stateOrProvinceName'] = 'ST';
_shortNames['O'] = oids['organizationName'];
_shortNames['organizationName'] = 'O';
_shortNames['OU'] = oids['organizationalUnitName'];
_shortNames['organizationalUnitName'] = 'OU';
_shortNames['E'] = oids['emailAddress'];
_shortNames['emailAddress'] = 'E';

// validator for an SubjectPublicKeyInfo structure
// Note: Currently only works with an RSA public key
var publicKeyValidator = {
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
      captureAsn1: 'rsaPublicKey'
    }]
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
    capture: 'publicKeyModulus'
  }, {
    // publicExponent (e)
    name: 'RSAPublicKey.exponent',
    tagClass: asn1.Class.UNIVERSAL,
    type: asn1.Type.INTEGER,
    constructed: false,
    capture: 'publicKeyExponent'
  }]
};

// validator for an X.509v3 certificate
var x509CertificateValidator = {
  name: 'Certificate',
  tagClass: asn1.Class.UNIVERSAL,
  type: asn1.Type.SEQUENCE,
  constructed: true,
  value: [{
    name: 'Certificate.TBSCertificate',
    tagClass: asn1.Class.UNIVERSAL,
    type: asn1.Type.SEQUENCE,
    constructed: true,
    captureAsn1: 'tbsCertificate',
    value: [{
      name: 'Certificate.TBSCertificate.version',
      tagClass: asn1.Class.CONTEXT_SPECIFIC,
      type: 0,
      constructed: true,
      optional: true,
      value: [{
        name: 'Certificate.TBSCertificate.version.integer',
        tagClass: asn1.Class.UNIVERSAL,
        type: asn1.Type.INTEGER,
        constructed: false,
        capture: 'certVersion'
      }]
    }, {
      name: 'Certificate.TBSCertificate.serialNumber',
      tagClass: asn1.Class.UNIVERSAL,
      type: asn1.Type.INTEGER,
      constructed: false,
      capture: 'certSerialNumber'
    }, {
      name: 'Certificate.TBSCertificate.signature',
      tagClass: asn1.Class.UNIVERSAL,
      type: asn1.Type.SEQUENCE,
      constructed: true,
      value: [{
        name: 'Certificate.TBSCertificate.signature.algorithm',
        tagClass: asn1.Class.UNIVERSAL,
        type: asn1.Type.OID,
        constructed: false,
        capture: 'certinfoSignatureOid'
      }, {
        name: 'Certificate.TBSCertificate.signature.parameters',
        tagClass: asn1.Class.UNIVERSAL,
        optional: true,
        captureAsn1: 'certinfoSignatureParams'
      }]
    }, {
      name: 'Certificate.TBSCertificate.issuer',
      tagClass: asn1.Class.UNIVERSAL,
      type: asn1.Type.SEQUENCE,
      constructed: true,
      captureAsn1: 'certIssuer'
    }, {
      name: 'Certificate.TBSCertificate.validity',
      tagClass: asn1.Class.UNIVERSAL,
      type: asn1.Type.SEQUENCE,
      constructed: true,
      // Note: UTC and generalized times may both appear so the capture
      // names are based on their detected order, the names used below
      // are only for the common case, which validity time really means
      // "notBefore" and which means "notAfter" will be determined by order
      value: [{
        // notBefore (Time) (UTC time case)
        name: 'Certificate.TBSCertificate.validity.notBefore (utc)',
        tagClass: asn1.Class.UNIVERSAL,
        type: asn1.Type.UTCTIME,
        constructed: false,
        optional: true,
        capture: 'certValidity1UTCTime'
      }, {
        // notBefore (Time) (generalized time case)
        name: 'Certificate.TBSCertificate.validity.notBefore (generalized)',
        tagClass: asn1.Class.UNIVERSAL,
        type: asn1.Type.GENERALIZEDTIME,
        constructed: false,
        optional: true,
        capture: 'certValidity2GeneralizedTime'
      }, {
        // notAfter (Time) (only UTC time is supported)
        name: 'Certificate.TBSCertificate.validity.notAfter (utc)',
        tagClass: asn1.Class.UNIVERSAL,
        type: asn1.Type.UTCTIME,
        constructed: false,
        optional: true,
        capture: 'certValidity3UTCTime'
      }, {
        // notAfter (Time) (only UTC time is supported)
        name: 'Certificate.TBSCertificate.validity.notAfter (generalized)',
        tagClass: asn1.Class.UNIVERSAL,
        type: asn1.Type.GENERALIZEDTIME,
        constructed: false,
        optional: true,
        capture: 'certValidity4GeneralizedTime'
      }]
    }, {
      // Name (subject) (RDNSequence)
      name: 'Certificate.TBSCertificate.subject',
      tagClass: asn1.Class.UNIVERSAL,
      type: asn1.Type.SEQUENCE,
      constructed: true,
      captureAsn1: 'certSubject'
    },
      // SubjectPublicKeyInfo
      publicKeyValidator,
    {
      // issuerUniqueID (optional)
      name: 'Certificate.TBSCertificate.issuerUniqueID',
      tagClass: asn1.Class.CONTEXT_SPECIFIC,
      type: 1,
      constructed: true,
      optional: true,
      value: [{
        name: 'Certificate.TBSCertificate.issuerUniqueID.id',
        tagClass: asn1.Class.UNIVERSAL,
        type: asn1.Type.BITSTRING,
        constructed: false,
        capture: 'certIssuerUniqueId'
      }]
    }, {
      // subjectUniqueID (optional)
      name: 'Certificate.TBSCertificate.subjectUniqueID',
      tagClass: asn1.Class.CONTEXT_SPECIFIC,
      type: 2,
      constructed: true,
      optional: true,
      value: [{
        name: 'Certificate.TBSCertificate.subjectUniqueID.id',
        tagClass: asn1.Class.UNIVERSAL,
        type: asn1.Type.BITSTRING,
        constructed: false,
        capture: 'certSubjectUniqueId'
      }]
    }, {
      // Extensions (optional)
      name: 'Certificate.TBSCertificate.extensions',
      tagClass: asn1.Class.CONTEXT_SPECIFIC,
      type: 3,
      constructed: true,
      captureAsn1: 'certExtensions',
      optional: true
    }]
  }, {
    // AlgorithmIdentifier (signature algorithm)
    name: 'Certificate.signatureAlgorithm',
    tagClass: asn1.Class.UNIVERSAL,
    type: asn1.Type.SEQUENCE,
    constructed: true,
    value: [{
      // algorithm
      name: 'Certificate.signatureAlgorithm.algorithm',
      tagClass: asn1.Class.UNIVERSAL,
      type: asn1.Type.OID,
      constructed: false,
      capture: 'certSignatureOid'
    }, {
      name: 'Certificate.TBSCertificate.signature.parameters',
      tagClass: asn1.Class.UNIVERSAL,
      optional: true,
      captureAsn1: 'certSignatureParams'
    }]
  }, {
    // SignatureValue
    name: 'Certificate.signatureValue',
    tagClass: asn1.Class.UNIVERSAL,
    type: asn1.Type.BITSTRING,
    constructed: false,
    capture: 'certSignature'
  }]
};

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
    capture: 'privateKeyVersion'
  }, {
    // modulus (n)
    name: 'RSAPrivateKey.modulus',
    tagClass: asn1.Class.UNIVERSAL,
    type: asn1.Type.INTEGER,
    constructed: false,
    capture: 'privateKeyModulus'
  }, {
    // publicExponent (e)
    name: 'RSAPrivateKey.publicExponent',
    tagClass: asn1.Class.UNIVERSAL,
    type: asn1.Type.INTEGER,
    constructed: false,
    capture: 'privateKeyPublicExponent'
  }, {
    // privateExponent (d)
    name: 'RSAPrivateKey.privateExponent',
    tagClass: asn1.Class.UNIVERSAL,
    type: asn1.Type.INTEGER,
    constructed: false,
    capture: 'privateKeyPrivateExponent'
  }, {
    // prime1 (p)
    name: 'RSAPrivateKey.prime1',
    tagClass: asn1.Class.UNIVERSAL,
    type: asn1.Type.INTEGER,
    constructed: false,
    capture: 'privateKeyPrime1'
  }, {
    // prime2 (q)
    name: 'RSAPrivateKey.prime2',
    tagClass: asn1.Class.UNIVERSAL,
    type: asn1.Type.INTEGER,
    constructed: false,
    capture: 'privateKeyPrime2'
  }, {
    // exponent1 (d mod (p-1))
    name: 'RSAPrivateKey.exponent1',
    tagClass: asn1.Class.UNIVERSAL,
    type: asn1.Type.INTEGER,
    constructed: false,
    capture: 'privateKeyExponent1'
  }, {
    // exponent2 (d mod (q-1))
    name: 'RSAPrivateKey.exponent2',
    tagClass: asn1.Class.UNIVERSAL,
    type: asn1.Type.INTEGER,
    constructed: false,
    capture: 'privateKeyExponent2'
  }, {
    // coefficient ((inverse of q) mod p)
    name: 'RSAPrivateKey.coefficient',
    tagClass: asn1.Class.UNIVERSAL,
    type: asn1.Type.INTEGER,
    constructed: false,
    capture: 'privateKeyCoefficient'
  }]
};

// validator for an EncryptedPrivateKeyInfo structure
// Note: Currently only works w/algorithm params
var encryptedPrivateKeyValidator = {
  name: 'EncryptedPrivateKeyInfo',
  tagClass: asn1.Class.UNIVERSAL,
  type: asn1.Type.SEQUENCE,
  constructed: true,
  value: [{
    name: 'EncryptedPrivateKeyInfo.encryptionAlgorithm',
    tagClass: asn1.Class.UNIVERSAL,
    type: asn1.Type.SEQUENCE,
    constructed: true,
    value: [{
      name: 'AlgorithmIdentifier.algorithm',
      tagClass: asn1.Class.UNIVERSAL,
      type: asn1.Type.OID,
      constructed: false,
      capture: 'encryptionOid'
    }, {
      name: 'AlgorithmIdentifier.parameters',
      tagClass: asn1.Class.UNIVERSAL,
      type: asn1.Type.SEQUENCE,
      constructed: true,
      captureAsn1: 'encryptionParams'
    }]
  }, {
    // encryptedData
    name: 'EncryptedPrivateKeyInfo.encryptedData',
    tagClass: asn1.Class.UNIVERSAL,
    type: asn1.Type.OCTETSTRING,
    constructed: false,
    capture: 'encryptedData'
  }]
};

// validator for a PBES2Algorithms structure
// Note: Currently only works w/PBKDF2 + AES encryption schemes
var PBES2AlgorithmsValidator = {
  name: 'PBES2Algorithms',
  tagClass: asn1.Class.UNIVERSAL,
  type: asn1.Type.SEQUENCE,
  constructed: true,
  value: [{
    name: 'PBES2Algorithms.keyDerivationFunc',
    tagClass: asn1.Class.UNIVERSAL,
    type: asn1.Type.SEQUENCE,
    constructed: true,
    value: [{
      name: 'PBES2Algorithms.keyDerivationFunc.oid',
      tagClass: asn1.Class.UNIVERSAL,
      type: asn1.Type.OID,
      constructed: false,
      capture: 'kdfOid'
    }, {
      name: 'PBES2Algorithms.params',
      tagClass: asn1.Class.UNIVERSAL,
      type: asn1.Type.SEQUENCE,
      constructed: true,
      value: [{
        name: 'PBES2Algorithms.params.salt',
        tagClass: asn1.Class.UNIVERSAL,
        type: asn1.Type.OCTETSTRING,
        constructed: false,
        capture: 'kdfSalt'
      }, {
        name: 'PBES2Algorithms.params.iterationCount',
        tagClass: asn1.Class.UNIVERSAL,
        type: asn1.Type.INTEGER,
        onstructed: true,
        capture: 'kdfIterationCount'
      }]
    }]
  }, {
    name: 'PBES2Algorithms.encryptionScheme',
    tagClass: asn1.Class.UNIVERSAL,
    type: asn1.Type.SEQUENCE,
    constructed: true,
    value: [{
      name: 'PBES2Algorithms.encryptionScheme.oid',
      tagClass: asn1.Class.UNIVERSAL,
      type: asn1.Type.OID,
      constructed: false,
      capture: 'encOid'
    }, {
      name: 'PBES2Algorithms.encryptionScheme.iv',
      tagClass: asn1.Class.UNIVERSAL,
      type: asn1.Type.OCTETSTRING,
      constructed: false,
      capture: 'encIv'
    }]
  }]
};

var pkcs12PbeParamsValidator = {
  name: 'pkcs-12PbeParams',
  tagClass: asn1.Class.UNIVERSAL,
  type: asn1.Type.SEQUENCE,
  constructed: true,
  value: [{
    name: 'pkcs-12PbeParams.salt',
    tagClass: asn1.Class.UNIVERSAL,
    type: asn1.Type.OCTETSTRING,
    constructed: false,
    capture: 'salt'
  }, {
    name: 'pkcs-12PbeParams.iterations',
    tagClass: asn1.Class.UNIVERSAL,
    type: asn1.Type.INTEGER,
    constructed: false,
    capture: 'iterations'
  }]
};

var rsassaPssParameterValidator = {
  name: 'rsapss',
  tagClass: asn1.Class.UNIVERSAL,
  type: asn1.Type.SEQUENCE,
  constructed: true,
  value: [{
    name: 'rsapss.hashAlgorithm',
    tagClass: asn1.Class.CONTEXT_SPECIFIC,
    type: 0,
    constructed: true,
    value: [{
      name: 'rsapss.hashAlgorithm.AlgorithmIdentifier',
      tagClass: asn1.Class.UNIVERSAL,
      type: asn1.Class.SEQUENCE,
      constructed: true,
      optional: true,
      value: [{
        name: 'rsapss.hashAlgorithm.AlgorithmIdentifier.algorithm',
        tagClass: asn1.Class.UNIVERSAL,
        type: asn1.Type.OID,
        constructed: false,
        capture: 'hashOid'
        /* parameter block omitted, for SHA1 NULL anyhow. */
      }]
    }]
  }, {
    name: 'rsapss.maskGenAlgorithm',
    tagClass: asn1.Class.CONTEXT_SPECIFIC,
    type: 1,
    constructed: true,
    value: [{
      name: 'rsapss.maskGenAlgorithm.AlgorithmIdentifier',
      tagClass: asn1.Class.UNIVERSAL,
      type: asn1.Class.SEQUENCE,
      constructed: true,
      optional: true,
      value: [{
        name: 'rsapss.maskGenAlgorithm.AlgorithmIdentifier.algorithm',
        tagClass: asn1.Class.UNIVERSAL,
        type: asn1.Type.OID,
        constructed: false,
        capture: 'maskGenOid'
      }, {
        name: 'rsapss.maskGenAlgorithm.AlgorithmIdentifier.params',
        tagClass: asn1.Class.UNIVERSAL,
        type: asn1.Type.SEQUENCE,
        constructed: true,
        value: [{
          name: 'rsapss.maskGenAlgorithm.AlgorithmIdentifier.params.algorithm',
          tagClass: asn1.Class.UNIVERSAL,
          type: asn1.Type.OID,
          constructed: false,
          capture: 'maskGenHashOid'
          /* parameter block omitted, for SHA1 NULL anyhow. */
        }]
      }]
    }]
  }, {
    name: 'rsapss.saltLength',
    tagClass: asn1.Class.CONTEXT_SPECIFIC,
    type: 2,
    optional: true,
    value: [{
      name: 'rsapss.saltLength.saltLength',
      tagClass: asn1.Class.UNIVERSAL,
      type: asn1.Class.INTEGER,
      constructed: false,
      capture: 'saltLength'
    }]
  }, {
    name: 'rsapss.trailerField',
    tagClass: asn1.Class.CONTEXT_SPECIFIC,
    type: 3,
    optional: true,
    value: [{
      name: 'rsapss.trailer.trailer',
      tagClass: asn1.Class.UNIVERSAL,
      type: asn1.Class.INTEGER,
      constructed: false,
      capture: 'trailer'
    }]
  }]
};

// validator for a CertificationRequestInfo structure
var certificationRequestInfoValidator = {
  name: 'CertificationRequestInfo',
  tagClass: asn1.Class.UNIVERSAL,
  type: asn1.Type.SEQUENCE,
  constructed: true,
  captureAsn1: 'certificationRequestInfo',
  value: [{
    name: 'CertificationRequestInfo.integer',
    tagClass: asn1.Class.UNIVERSAL,
    type: asn1.Type.INTEGER,
    constructed: false,
    capture: 'certificationRequestInfoVersion'
  }, {
    // Name (subject) (RDNSequence)
    name: 'CertificationRequestInfo.subject',
    tagClass: asn1.Class.UNIVERSAL,
    type: asn1.Type.SEQUENCE,
    constructed: true,
    captureAsn1: 'certificationRequestInfoSubject'
  },
  // SubjectPublicKeyInfo
  publicKeyValidator,
  {
    name: 'CertificationRequestInfo.attributes',
    tagClass: asn1.Class.CONTEXT_SPECIFIC,
    type: 0,
    constructed: true,
    optional: true,
    capture: 'certificationRequestInfoAttributes',
    value: [{
      name: 'CertificationRequestInfo.attributes',
      tagClass: asn1.Class.UNIVERSAL,
      type: asn1.Type.SEQUENCE,
      constructed: true,
      value: [{
        name: 'CertificationRequestInfo.attributes.type',
        tagClass: asn1.Class.UNIVERSAL,
        type: asn1.Type.OID,
        constructed: false
      }, {
        name: 'CertificationRequestInfo.attributes.value',
        tagClass: asn1.Class.UNIVERSAL,
        type: asn1.Type.SET,
        constructed: true
      }]
    }]
  }]
};

// validator for a CertificationRequest structure
var certificationRequestValidator = {
  name: 'CertificationRequest',
  tagClass: asn1.Class.UNIVERSAL,
  type: asn1.Type.SEQUENCE,
  constructed: true,
  captureAsn1: 'csr',
  value: [
    certificationRequestInfoValidator, {
    // AlgorithmIdentifier (signature algorithm)
    name: 'CertificationRequest.signatureAlgorithm',
    tagClass: asn1.Class.UNIVERSAL,
    type: asn1.Type.SEQUENCE,
    constructed: true,
    value: [{
      // algorithm
      name: 'CertificationRequest.signatureAlgorithm.algorithm',
      tagClass: asn1.Class.UNIVERSAL,
      type: asn1.Type.OID,
      constructed: false,
      capture: 'csrSignatureOid'
    }, {
      name: 'CertificationRequest.signatureAlgorithm.parameters',
      tagClass: asn1.Class.UNIVERSAL,
      optional: true,
      captureAsn1: 'csrSignatureParams'
    }]
  }, {
    // signature
    name: 'CertificationRequest.signature',
    tagClass: asn1.Class.UNIVERSAL,
    type: asn1.Type.BITSTRING,
    constructed: false,
    capture: 'csrSignature'
  }]
};

/**
 * Converts an RDNSequence of ASN.1 DER-encoded RelativeDistinguishedName
 * sets into an array with objects that have type and value properties.
 *
 * @param rdn the RDNSequence to convert.
 * @param md a message digest to append type and value to if provided.
 */
pki.RDNAttributesAsArray = function(rdn, md) {
  var rval = [];

  // each value in 'rdn' in is a SET of RelativeDistinguishedName
  var set, attr, obj;
  for(var si = 0; si < rdn.value.length; ++si) {
    // get the RelativeDistinguishedName set
    set = rdn.value[si];

    // each value in the SET is an AttributeTypeAndValue sequence
    // containing first a type (an OID) and second a value (defined by
    // the OID)
    for(var i = 0; i < set.value.length; ++i) {
      obj = {};
      attr = set.value[i];
      obj.type = asn1.derToOid(attr.value[0].value);
      obj.value = attr.value[1].value;
      obj.valueTagClass = attr.value[1].type;
      // if the OID is known, get its name and short name
      if(obj.type in oids) {
        obj.name = oids[obj.type];
        if(obj.name in _shortNames) {
          obj.shortName = _shortNames[obj.name];
        }
      }
      if(md) {
        md.update(obj.type);
        md.update(obj.value);
      }
      rval.push(obj);
    }
  }

  return rval;
};

/**
 * Converts ASN.1 CRIAttributes into an array with objects that have type and
 * value properties.
 *
 * @param attributes the CRIAttributes to convert.
 */
pki.CRIAttributesAsArray = function(attributes) {
  var rval = [];

  // each value in 'attributes' in is a SEQUENCE with an OID and a SET
  for(var si = 0; si < attributes.length; ++si) {
    // get the attribute sequence
    var seq = attributes[si];

    // each value in the SEQUENCE containing first a type (an OID) and
    // second a set of values (defined by the OID)
    var type = asn1.derToOid(seq.value[0].value);
    var values = seq.value[1].value;
    for(var vi = 0; vi < values.length; ++vi) {
      var obj = {};
      obj.type = type;
      obj.value = values[vi].value;
      obj.valueTagClass = values[vi].type;
      // if the OID is known, get its name and short name
      if(obj.type in oids) {
        obj.name = oids[obj.type];
        if(obj.name in _shortNames) {
          obj.shortName = _shortNames[obj.name];
        }
      }
      rval.push(obj);
    }
  }

  return rval;
};

/**
 * Gets an issuer or subject attribute from its name, type, or short name.
 *
 * @param obj the issuer or subject object.
 * @param options a short name string or an object with:
 *          shortName the short name for the attribute.
 *          name the name for the attribute.
 *          type the type for the attribute.
 *
 * @return the attribute.
 */
var _getAttribute = function(obj, options) {
  if(typeof options === 'string') {
    options = {shortName: options};
  }

  var rval = null;
  var attr;
  for(var i = 0; rval === null && i < obj.attributes.length; ++i) {
    attr = obj.attributes[i];
    if(options.type && options.type === attr.type) {
      rval = attr;
    }
    else if(options.name && options.name === attr.name) {
      rval = attr;
    }
    else if(options.shortName && options.shortName === attr.shortName) {
      rval = attr;
    }
  }
  return rval;
};

/**
 * Converts an ASN.1 extensions object (with extension sequences as its
 * values) into an array of extension objects with types and values.
 *
 * Supported extensions:
 *
 * id-ce-keyUsage OBJECT IDENTIFIER ::=  { id-ce 15 }
 * KeyUsage ::= BIT STRING {
 *   digitalSignature        (0),
 *   nonRepudiation          (1),
 *   keyEncipherment         (2),
 *   dataEncipherment        (3),
 *   keyAgreement            (4),
 *   keyCertSign             (5),
 *   cRLSign                 (6),
 *   encipherOnly            (7),
 *   decipherOnly            (8)
 * }
 *
 * id-ce-basicConstraints OBJECT IDENTIFIER ::=  { id-ce 19 }
 * BasicConstraints ::= SEQUENCE {
 *   cA                      BOOLEAN DEFAULT FALSE,
 *   pathLenConstraint       INTEGER (0..MAX) OPTIONAL
 * }
 *
 * subjectAltName EXTENSION ::= {
 *   SYNTAX GeneralNames
 *   IDENTIFIED BY id-ce-subjectAltName
 * }
 *
 * GeneralNames ::= SEQUENCE SIZE (1..MAX) OF GeneralName
 *
 * GeneralName ::= CHOICE {
 *   otherName      [0] INSTANCE OF OTHER-NAME,
 *   rfc822Name     [1] IA5String,
 *   dNSName        [2] IA5String,
 *   x400Address    [3] ORAddress,
 *   directoryName  [4] Name,
 *   ediPartyName   [5] EDIPartyName,
 *   uniformResourceIdentifier [6] IA5String,
 *   IPAddress      [7] OCTET STRING,
 *   registeredID   [8] OBJECT IDENTIFIER
 * }
 *
 * OTHER-NAME ::= TYPE-IDENTIFIER
 *
 * EDIPartyName ::= SEQUENCE {
 *   nameAssigner [0] DirectoryString {ub-name} OPTIONAL,
 *   partyName    [1] DirectoryString {ub-name}
 * }
 *
 * @param exts the extensions ASN.1 with extension sequences to parse.
 *
 * @return the array.
 */
var _parseExtensions = function(exts) {
  var rval = [];

  var e, ext, extseq;
  for(var i = 0; i < exts.value.length; ++i) {
    // get extension sequence
    extseq = exts.value[i];
    for(var ei = 0; ei < extseq.value.length; ++ei) {
      // an extension has:
      // [0] extnID      OBJECT IDENTIFIER
      // [1] critical    BOOLEAN DEFAULT FALSE
      // [2] extnValue   OCTET STRING
      ext = extseq.value[ei];
      e = {};
      e.id = asn1.derToOid(ext.value[0].value);
      e.critical = false;
      if(ext.value[1].type === asn1.Type.BOOLEAN) {
        e.critical = (ext.value[1].value.charCodeAt(0) !== 0x00);
        e.value = ext.value[2].value;
      }
      else {
        e.value = ext.value[1].value;
      }
      // if the oid is known, get its name
      if(e.id in oids) {
        e.name = oids[e.id];

        // handle key usage
        if(e.name === 'keyUsage') {
          // get value as BIT STRING
          var ev = asn1.fromDer(e.value);
          var b2 = 0x00;
          var b3 = 0x00;
          if(ev.value.length > 1) {
            // skip first byte, just indicates unused bits which
            // will be padded with 0s anyway
            // get bytes with flag bits
            b2 = ev.value.charCodeAt(1);
            b3 = ev.value.length > 2 ? ev.value.charCodeAt(2) : 0;
          }
          // set flags
          e.digitalSignature = (b2 & 0x80) === 0x80;
          e.nonRepudiation = (b2 & 0x40) === 0x40;
          e.keyEncipherment = (b2 & 0x20) === 0x20;
          e.dataEncipherment = (b2 & 0x10) === 0x10;
          e.keyAgreement = (b2 & 0x08) === 0x08;
          e.keyCertSign = (b2 & 0x04) === 0x04;
          e.cRLSign = (b2 & 0x02) === 0x02;
          e.encipherOnly = (b2 & 0x01) === 0x01;
          e.decipherOnly = (b3 & 0x80) === 0x80;
        }
        // handle basic constraints
        else if(e.name === 'basicConstraints') {
          // get value as SEQUENCE
          var ev = asn1.fromDer(e.value);
          // get cA BOOLEAN flag (defaults to false)
          if(ev.value.length > 0) {
            e.cA = (ev.value[0].value.charCodeAt(0) !== 0x00);
          }
          else {
            e.cA = false;
          }
          // get path length constraint
          if(ev.value.length > 1) {
            var tmp = forge.util.createBuffer(ev.value[1].value);
            e.pathLenConstraint = tmp.getInt(tmp.length() << 3);
          }
        }
        // handle extKeyUsage
        else if(e.name === 'extKeyUsage') {
          // value is a SEQUENCE of OIDs
          var ev = asn1.fromDer(e.value);
          for(var vi = 0; vi < ev.value.length; ++vi) {
            var oid = asn1.derToOid(ev.value[vi].value);
            if(oid in oids) {
              e[oids[oid]] = true;
            }
            else {
              e[oid] = true;
            }
          }
        }
        // handle nsCertType
        else if(e.name === 'nsCertType') {
          // get value as BIT STRING
          var ev = asn1.fromDer(e.value);
          var b2 = 0x00;
          if(ev.value.length > 1) {
            // skip first byte, just indicates unused bits which
            // will be padded with 0s anyway
            // get bytes with flag bits
            b2 = ev.value.charCodeAt(1);
          }
          // set flags
          e.client = (b2 & 0x80) === 0x80;
          e.server = (b2 & 0x40) === 0x40;
          e.email = (b2 & 0x20) === 0x20;
          e.objsign = (b2 & 0x10) === 0x10;
          e.reserved = (b2 & 0x08) === 0x08;
          e.sslCA = (b2 & 0x04) === 0x04;
          e.emailCA = (b2 & 0x02) === 0x02;
          e.objCA = (b2 & 0x01) === 0x01;
        }
        // handle subjectAltName/issuerAltName
        else if(
          e.name === 'subjectAltName' ||
          e.name === 'issuerAltName') {
          e.altNames = [];

          // ev is a SYNTAX SEQUENCE
          var gn;
          var ev = asn1.fromDer(e.value);
          for(var n = 0; n < ev.value.length; ++n) {
            // get GeneralName
            gn = ev.value[n];

            var altName = {
              type: gn.type,
              value: gn.value
            };
            e.altNames.push(altName);

            // Note: Support for types 1,2,6,7,8
            switch(gn.type) {
            // rfc822Name
            case 1:
            // dNSName
            case 2:
            // uniformResourceIdentifier (URI)
            case 6:
              break;
            // IPAddress
            case 7:
              // FIXME: convert to IPv4 dotted string/IPv6
              break;
            // registeredID
            case 8:
              altName.oid = asn1.derToOid(gn.value);
              break;
            default:
              // unsupported
            }
          }
        }
        else if(e.name === 'subjectKeyIdentifier') {
          // value is an OCTETSTRING w/the hash of the key-type specific
          // public key structure (eg: RSAPublicKey)
          var ev = asn1.fromDer(e.value);
          e.subjectKeyIdentifier = forge.util.bytesToHex(ev.value);
        }
      }
      rval.push(e);
    }
  }

  return rval;
};

/**
 * NOTE: THIS METHOD IS DEPRECATED. Use pem.decode() instead.
 *
 * Converts PEM-formatted data to DER.
 *
 * @param pem the PEM-formatted data.
 *
 * @return the DER-formatted data.
 */
pki.pemToDer = function(pem) {
  var msg = forge.pem.decode(pem)[0];
  if(msg.procType && msg.procType.type === 'ENCRYPTED') {
    throw {
      message: 'Could not convert PEM to DER; PEM is encrypted.'
    };
  }
  return forge.util.createBuffer(msg.body);
};

/**
 * Converts a positive BigInteger into 2's-complement big-endian bytes.
 *
 * @param b the big integer to convert.
 *
 * @return the bytes.
 */
var _bnToBytes = function(b) {
  // prepend 0x00 if first byte >= 0x80
  var hex = b.toString(16);
  if(hex[0] >= '8') {
    hex = '00' + hex;
  }
  return forge.util.hexToBytes(hex);
};

/**
 * Converts signature parameters from ASN.1 structure.
 *
 * Currently only RSASSA-PSS supported.  The PKCS#1 v1.5 signature scheme had
 * no parameters.
 *
 * RSASSA-PSS-params  ::=  SEQUENCE  {
 *   hashAlgorithm      [0] HashAlgorithm DEFAULT
 *                             sha1Identifier,
 *   maskGenAlgorithm   [1] MaskGenAlgorithm DEFAULT
 *                             mgf1SHA1Identifier,
 *   saltLength         [2] INTEGER DEFAULT 20,
 *   trailerField       [3] INTEGER DEFAULT 1
 * }
 *
 * HashAlgorithm  ::=  AlgorithmIdentifier
 *
 * MaskGenAlgorithm  ::=  AlgorithmIdentifier
 *
 * AlgorithmIdentifer ::= SEQUENCE {
 *   algorithm OBJECT IDENTIFIER,
 *   parameters ANY DEFINED BY algorithm OPTIONAL
 * }
 *
 * @param oid The OID specifying the signature algorithm
 * @param obj The ASN.1 structure holding the parameters
 * @param fillDefaults Whether to use return default values where omitted
 * @return signature parameter object
 */
var _readSignatureParameters = function(oid, obj, fillDefaults) {
  var params = {};

  if(oid !== oids['RSASSA-PSS']) {
    return params;
  }

  if(fillDefaults) {
    params = {
      hash: {
        algorithmOid: oids['sha1']
      },
      mgf: {
        algorithmOid: oids['mgf1'],
        hash: {
          algorithmOid: oids['sha1']
        }
      },
      saltLength: 20
    };
  }

  var capture = {};
  var errors = [];
  if(!asn1.validate(obj, rsassaPssParameterValidator, capture, errors)) {
    throw {
      message: 'Cannot read RSASSA-PSS parameter block.',
      errors: errors
    };
  }

  if(capture.hashOid !== undefined) {
    params.hash = params.hash || {};
    params.hash.algorithmOid = asn1.derToOid(capture.hashOid);
  }

  if(capture.maskGenOid !== undefined) {
    params.mgf = params.mgf || {};
    params.mgf.algorithmOid = asn1.derToOid(capture.maskGenOid);
    params.mgf.hash = params.mgf.hash || {};
    params.mgf.hash.algorithmOid = asn1.derToOid(capture.maskGenHashOid);
  }

  if(capture.saltLength !== undefined) {
    params.saltLength = capture.saltLength.charCodeAt(0);
  }

  return params;
};

/**
 * Converts an X.509 certificate from PEM format.
 *
 * Note: If the certificate is to be verified then compute hash should
 * be set to true. This will scan the TBSCertificate part of the ASN.1
 * object while it is converted so it doesn't need to be converted back
 * to ASN.1-DER-encoding later.
 *
 * @param pem the PEM-formatted certificate.
 * @param computeHash true to compute the hash for verification.
 * @param strict true to be strict when checking ASN.1 value lengths, false to
 *          allow truncated values (default: true).
 *
 * @return the certificate.
 */
pki.certificateFromPem = function(pem, computeHash, strict) {
  var msg = forge.pem.decode(pem)[0];

  if(msg.type !== 'CERTIFICATE' &&
    msg.type !== 'X509 CERTIFICATE' &&
    msg.type !== 'TRUSTED CERTIFICATE') {
    throw {
      message: 'Could not convert certificate from PEM; PEM header type is ' +
        'not "CERTIFICATE", "X509 CERTIFICATE", or "TRUSTED CERTIFICATE".',
      headerType: msg.type
    };
  }
  if(msg.procType && msg.procType.type === 'ENCRYPTED') {
    throw {
      message: 'Could not convert certificate from PEM; PEM is encrypted.'
    };
  }

  // convert DER to ASN.1 object
  var obj = asn1.fromDer(msg.body, strict);

  return pki.certificateFromAsn1(obj, computeHash);
};

/**
 * Converts an X.509 certificate to PEM format.
 *
 * @param cert the certificate.
 * @param maxline the maximum characters per line, defaults to 64.
 *
 * @return the PEM-formatted certificate.
 */
pki.certificateToPem = function(cert, maxline) {
  // convert to ASN.1, then DER, then PEM-encode
  var msg = {
    type: 'CERTIFICATE',
    body: asn1.toDer(pki.certificateToAsn1(cert)).getBytes()
  };
  return forge.pem.encode(msg, {maxline: maxline});
};

/**
 * Converts an RSA public key from PEM format.
 *
 * @param pem the PEM-formatted public key.
 *
 * @return the public key.
 */
pki.publicKeyFromPem = function(pem) {
  var msg = forge.pem.decode(pem)[0];

  if(msg.type !== 'PUBLIC KEY' && msg.type !== 'RSA PUBLIC KEY') {
    throw {
      message: 'Could not convert public key from PEM; PEM header type is ' +
        'not "PUBLIC KEY" or "RSA PUBLIC KEY".',
      headerType: msg.type
    };
  }
  if(msg.procType && msg.procType.type === 'ENCRYPTED') {
    throw {
      message: 'Could not convert public key from PEM; PEM is encrypted.'
    };
  }

  // convert DER to ASN.1 object
  var obj = asn1.fromDer(msg.body);

  return pki.publicKeyFromAsn1(obj);
};

/**
 * Converts an RSA public key to PEM format (using a SubjectPublicKeyInfo).
 *
 * @param key the public key.
 * @param maxline the maximum characters per line, defaults to 64.
 *
 * @return the PEM-formatted public key.
 */
pki.publicKeyToPem = function(key, maxline) {
  // convert to ASN.1, then DER, then PEM-encode
  var msg = {
    type: 'PUBLIC KEY',
    body: asn1.toDer(pki.publicKeyToAsn1(key)).getBytes()
  };
  return forge.pem.encode(msg, {maxline: maxline});
};

/**
 * Converts an RSA public key to PEM format (using an RSAPublicKey).
 *
 * @param key the public key.
 * @param maxline the maximum characters per line, defaults to 64.
 *
 * @return the PEM-formatted public key.
 */
pki.publicKeyToRSAPublicKeyPem = function(key, maxline) {
  // convert to ASN.1, then DER, then PEM-encode
  var msg = {
    type: 'RSA PUBLIC KEY',
    body: asn1.toDer(pki.publicKeyToRSAPublicKey(key)).getBytes()
  };
  return forge.pem.encode(msg, {maxline: maxline});
};

/**
 * Converts an RSA private key from PEM format.
 *
 * @param pem the PEM-formatted private key.
 *
 * @return the private key.
 */
pki.privateKeyFromPem = function(pem) {
  var msg = forge.pem.decode(pem)[0];

  if(msg.type !== 'PRIVATE KEY' && msg.type !== 'RSA PRIVATE KEY') {
    throw {
      message: 'Could not convert private key from PEM; PEM header type is ' +
        'not "PRIVATE KEY" or "RSA PRIVATE KEY".',
      headerType: msg.type
    };
  }
  if(msg.procType && msg.procType.type === 'ENCRYPTED') {
    throw {
      message: 'Could not convert private key from PEM; PEM is encrypted.'
    };
  }

  // convert DER to ASN.1 object
  var obj = asn1.fromDer(msg.body);

  return pki.privateKeyFromAsn1(obj);
};

/**
 * Converts an RSA private key to PEM format.
 *
 * @param key the private key.
 * @param maxline the maximum characters per line, defaults to 64.
 *
 * @return the PEM-formatted private key.
 */
pki.privateKeyToPem = function(key, maxline) {
  // convert to ASN.1, then DER, then PEM-encode
  var msg = {
    type: 'RSA PRIVATE KEY',
    body: asn1.toDer(pki.privateKeyToAsn1(key)).getBytes()
  };
  return forge.pem.encode(msg, {maxline: maxline});
};

/**
 * Converts a PKCS#10 certification request (CSR) from PEM format.
 *
 * Note: If the certification request is to be verified then compute hash
 * should be set to true. This will scan the CertificationRequestInfo part of
 * the ASN.1 object while it is converted so it doesn't need to be converted
 * back to ASN.1-DER-encoding later.
 *
 * @param pem the PEM-formatted certificate.
 * @param computeHash true to compute the hash for verification.
 * @param strict true to be strict when checking ASN.1 value lengths, false to
 *          allow truncated values (default: true).
 *
 * @return the certification request (CSR).
 */
pki.certificationRequestFromPem = function(pem, computeHash, strict) {
  var msg = forge.pem.decode(pem)[0];

  if(msg.type !== 'CERTIFICATE REQUEST') {
    throw {
      message: 'Could not convert certification request from PEM; PEM header ' +
        'type is not "CERTIFICATE REQUEST".',
      headerType: msg.type
    };
  }
  if(msg.procType && msg.procType.type === 'ENCRYPTED') {
    throw {
      message: 'Could not convert certification request from PEM; ' +
        'PEM is encrypted.'
    };
  }

  // convert DER to ASN.1 object
  var obj = asn1.fromDer(msg.body, strict);

  return pki.certificationRequestFromAsn1(obj, computeHash);
};

/**
 * Converts a PKCS#10 certification request (CSR) to PEM format.
 *
 * @param csr the certification request.
 * @param maxline the maximum characters per line, defaults to 64.
 *
 * @return the PEM-formatted certification request.
 */
pki.certificationRequestToPem = function(csr, maxline) {
  // convert to ASN.1, then DER, then PEM-encode
  var msg = {
    type: 'CERTIFICATE REQUEST',
    body: asn1.toDer(pki.certificationRequestToAsn1(csr)).getBytes()
  };
  return forge.pem.encode(msg, {maxline: maxline});
};

/**
 * Creates an empty X.509v3 RSA certificate.
 *
 * @return the certificate.
 */
pki.createCertificate = function() {
  var cert = {};
  cert.version = 0x02;
  cert.serialNumber = '00';
  cert.signatureOid = null;
  cert.signature = null;
  cert.siginfo = {};
  cert.siginfo.algorithmOid = null;
  cert.validity = {};
  cert.validity.notBefore = new Date();
  cert.validity.notAfter = new Date();

  cert.issuer = {};
  cert.issuer.getField = function(sn) {
    return _getAttribute(cert.issuer, sn);
  };
  cert.issuer.addField = function(attr) {
    _fillMissingFields([attr]);
    cert.issuer.attributes.push(attr);
  };
  cert.issuer.attributes = [];
  cert.issuer.hash = null;

  cert.subject = {};
  cert.subject.getField = function(sn) {
    return _getAttribute(cert.subject, sn);
  };
  cert.subject.addField = function(attr) {
    _fillMissingFields([attr]);
    cert.subject.attributes.push(attr);
  };
  cert.subject.attributes = [];
  cert.subject.hash = null;

  cert.extensions = [];
  cert.publicKey = null;
  cert.md = null;

  /**
   * Fills in missing fields in attributes.
   *
   * @param attrs the attributes to fill missing fields in.
   */
  var _fillMissingFields = function(attrs) {
    var attr;
    for(var i = 0; i < attrs.length; ++i) {
      attr = attrs[i];

      // populate missing name
      if(typeof(attr.name) === 'undefined') {
        if(attr.type && attr.type in pki.oids) {
          attr.name = pki.oids[attr.type];
        }
        else if(attr.shortName && attr.shortName in _shortNames) {
          attr.name = pki.oids[_shortNames[attr.shortName]];
        }
      }

      // populate missing type (OID)
      if(typeof(attr.type) === 'undefined') {
        if(attr.name && attr.name in pki.oids) {
          attr.type = pki.oids[attr.name];
        }
        else {
          throw {
            message: 'Attribute type not specified.',
            attribute: attr
          };
        }
      }

      // populate missing shortname
      if(typeof(attr.shortName) === 'undefined') {
        if(attr.name && attr.name in _shortNames) {
          attr.shortName = _shortNames[attr.name];
        }
      }

      if(typeof(attr.value) === 'undefined') {
        throw {
          message: 'Attribute value not specified.',
          attribute: attr
        };
      }
    }
  };

  /**
   * Sets the subject of this certificate.
   *
   * @param attrs the array of subject attributes to use.
   * @param uniqueId an optional a unique ID to use.
   */
  cert.setSubject = function(attrs, uniqueId) {
    // set new attributes, clear hash
    _fillMissingFields(attrs);
    cert.subject.attributes = attrs;
    delete cert.subject.uniqueId;
    if(uniqueId) {
      cert.subject.uniqueId = uniqueId;
    }
    cert.subject.hash = null;
  };

  /**
   * Sets the issuer of this certificate.
   *
   * @param attrs the array of issuer attributes to use.
   * @param uniqueId an optional a unique ID to use.
   */
  cert.setIssuer = function(attrs, uniqueId) {
    // set new attributes, clear hash
    _fillMissingFields(attrs);
    cert.issuer.attributes = attrs;
    delete cert.issuer.uniqueId;
    if(uniqueId) {
      cert.issuer.uniqueId = uniqueId;
    }
    cert.issuer.hash = null;
  };

  /**
   * Sets the extensions of this certificate.
   *
   * @param exts the array of extensions to use.
   */
  cert.setExtensions = function(exts) {
    var e;
    for(var i = 0; i < exts.length; ++i) {
      e = exts[i];

      // populate missing name
      if(typeof(e.name) === 'undefined') {
        if(e.id && e.id in pki.oids) {
          e.name = pki.oids[e.id];
        }
      }

      // populate missing id
      if(typeof(e.id) === 'undefined') {
        if(e.name && e.name in pki.oids) {
          e.id = pki.oids[e.name];
        }
        else {
          throw {
            message: 'Extension ID not specified.',
            extension: e
          };
        }
      }

      // handle missing value
      if(typeof(e.value) === 'undefined') {
        // value is a BIT STRING
        if(e.name === 'keyUsage') {
          // build flags
          var unused = 0;
          var b2 = 0x00;
          var b3 = 0x00;
          if(e.digitalSignature) {
            b2 |= 0x80;
            unused = 7;
          }
          if(e.nonRepudiation) {
            b2 |= 0x40;
            unused = 6;
          }
          if(e.keyEncipherment) {
            b2 |= 0x20;
            unused = 5;
          }
          if(e.dataEncipherment) {
            b2 |= 0x10;
            unused = 4;
          }
          if(e.keyAgreement) {
            b2 |= 0x08;
            unused = 3;
          }
          if(e.keyCertSign) {
            b2 |= 0x04;
            unused = 2;
          }
          if(e.cRLSign) {
            b2 |= 0x02;
            unused = 1;
          }
          if(e.encipherOnly) {
            b2 |= 0x01;
            unused = 0;
          }
          if(e.decipherOnly) {
            b3 |= 0x80;
            unused = 7;
          }

          // create bit string
          var value = String.fromCharCode(unused);
          if(b3 !== 0) {
            value += String.fromCharCode(b2) + String.fromCharCode(b3);
          }
          else if(b2 !== 0) {
            value += String.fromCharCode(b2);
          }
          e.value = asn1.create(
            asn1.Class.UNIVERSAL, asn1.Type.BITSTRING, false, value);
        }
        // basicConstraints is a SEQUENCE
        else if(e.name === 'basicConstraints') {
          e.value = asn1.create(
            asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, []);
          // cA BOOLEAN flag defaults to false
          if(e.cA) {
            e.value.value.push(asn1.create(
              asn1.Class.UNIVERSAL, asn1.Type.BOOLEAN, false,
              String.fromCharCode(0xFF)));
          }
          if(e.pathLenConstraint) {
            var num = e.pathLenConstraint;
            var tmp = forge.util.createBuffer();
            tmp.putInt(num, num.toString(2).length);
            e.value.value.push(asn1.create(
              asn1.Class.UNIVERSAL, asn1.Type.INTEGER, false,
              tmp.getBytes()));
          }
        }
        // extKeyUsage is a SEQUENCE of OIDs
        else if(e.name === 'extKeyUsage') {
          e.value = asn1.create(
            asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, []);
          var seq = e.value.value;
          for(var key in e) {
            if(e[key] !== true) {
              continue;
            }
            // key is name in OID map
            if(key in oids) {
              seq.push(asn1.create(asn1.Class.UNIVERSAL, asn1.Type.OID,
                false, asn1.oidToDer(oids[key]).getBytes()));
            }
            // assume key is an OID
            else if(key.indexOf('.') !== -1) {
              seq.push(asn1.create(asn1.Class.UNIVERSAL, asn1.Type.OID,
                false, asn1.oidToDer(key).getBytes()));
            }
          }
        }
        // nsCertType is a BIT STRING
        else if(e.name === 'nsCertType') {
          // build flags
          var unused = 0;
          var b2 = 0x00;

          if(e.client) {
            b2 |= 0x80;
            unused = 7;
          }
          if(e.server) {
            b2 |= 0x40;
            unused = 6;
          }
          if(e.email) {
            b2 |= 0x20;
            unused = 5;
          }
          if(e.objsign) {
            b2 |= 0x10;
            unused = 4;
          }
          if(e.reserved) {
            b2 |= 0x08;
            unused = 3;
          }
          if(e.sslCA) {
            b2 |= 0x04;
            unused = 2;
          }
          if(e.emailCA) {
            b2 |= 0x02;
            unused = 1;
          }
          if(e.objCA) {
            b2 |= 0x01;
            unused = 0;
          }

          // create bit string
          var value = String.fromCharCode(unused);
          if(b2 !== 0) {
            value += String.fromCharCode(b2);
          }
          e.value = asn1.create(
            asn1.Class.UNIVERSAL, asn1.Type.BITSTRING, false, value);
        }
        else if(e.name === 'subjectAltName' || e.name === 'issuerAltName') {
          // SYNTAX SEQUENCE
          e.value = asn1.create(
            asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, []);

          var altName;
          for(var n = 0; n < e.altNames.length; ++n) {
            altName = e.altNames[n];
            var value = altName.value;
            // handle OID
            if(altName.type === 8) {
              value = asn1.oidToDer(value);
            }
            e.value.value.push(asn1.create(
              asn1.Class.CONTEXT_SPECIFIC, altName.type, false,
              value));
          }
        }
        else if(e.name === 'subjectKeyIdentifier') {
          var ski = cert.generateSubjectKeyIdentifier();
          e.subjectKeyIdentifier = ski.toHex();
          // OCTETSTRING w/digest
          e.value = asn1.create(
            asn1.Class.UNIVERSAL, asn1.Type.OCTETSTRING, false, ski.getBytes());
        }

        // ensure value has been defined by now
        if(typeof(e.value) === 'undefined') {
          throw {
            message: 'Extension value not specified.',
            extension: e
          };
        }
      }
    }

    // set new extensions
    cert.extensions = exts;
  };

  /**
   * Gets an extension by its name or id.
   *
   * @param options the name to use or an object with:
   *          name the name to use.
   *          id the id to use.
   *
   * @return the extension or null if not found.
   */
  cert.getExtension = function(options) {
    if(typeof options === 'string') {
      options = {name: options};
    }

    var rval = null;
    var ext;
    for(var i = 0; rval === null && i < cert.extensions.length; ++i) {
      ext = cert.extensions[i];
      if(options.id && ext.id === options.id) {
        rval = ext;
      }
      else if(options.name && ext.name === options.name) {
        rval = ext;
      }
    }
    return rval;
  };

  /**
   * Signs this certificate using the given private key.
   *
   * @param key the private key to sign with.
   * @param md the message digest object to use (defaults to forge.md.sha1).
   */
  cert.sign = function(key, md) {
    // TODO: get signature OID from private key
    cert.md = md || forge.md.sha1.create();
    var algorithmOid = oids[cert.md.algorithm + 'WithRSAEncryption'];
    if(!algorithmOid) {
      throw {
        message: 'Could not compute certificate digest. ' +
          'Unknown message digest algorithm OID.',
        algorithm: cert.md.algorithm
      };
    }
    cert.signatureOid = cert.siginfo.algorithmOid = algorithmOid;

    // get TBSCertificate, convert to DER
    cert.tbsCertificate = pki.getTBSCertificate(cert);
    var bytes = asn1.toDer(cert.tbsCertificate);

    // digest and sign
    cert.md.update(bytes.getBytes());
    cert.signature = key.sign(cert.md);
  };

  /**
   * Attempts verify the signature on the passed certificate using this
   * certificate's public key.
   *
   * @param child the certificate to verify.
   *
   * @return true if verified, false if not.
   */
  cert.verify = function(child) {
    var rval = false;

    var md = child.md;
    if(md === null) {
      // check signature OID for supported signature types
      if(child.signatureOid in oids) {
        var oid = oids[child.signatureOid];
        switch(oid) {
        case 'sha1WithRSAEncryption':
          md = forge.md.sha1.create();
          break;
        case 'md5WithRSAEncryption':
          md = forge.md.md5.create();
          break;
        case 'sha256WithRSAEncryption':
          md = forge.md.sha256.create();
          break;
        case 'RSASSA-PSS':
          md = forge.md.sha256.create();
          break;
        }
      }
      if(md === null) {
        throw {
          message: 'Could not compute certificate digest. ' +
            'Unknown signature OID.',
          signatureOid: child.signatureOid
        };
      }

      // produce DER formatted TBSCertificate and digest it
      var tbsCertificate = child.tbsCertificate || pki.getTBSCertificate(child);
      var bytes = asn1.toDer(tbsCertificate);
      md.update(bytes.getBytes());
    }

    if(md !== null) {
      var scheme = undefined;

      switch(child.signatureOid) {
      case oids['sha1WithRSAEncryption']:
        scheme = undefined;  /* use PKCS#1 v1.5 padding scheme */
        break;
      case oids['RSASSA-PSS']:
        var hash, mgf;

        /* initialize mgf */
        hash = oids[child.signatureParameters.mgf.hash.algorithmOid];
        if(hash === undefined || forge.md[hash] === undefined) {
          throw {
            message: 'Unsupported MGF hash function.',
            oid: child.signatureParameters.mgf.hash.algorithmOid,
            name: hash
          };
        }

        mgf = oids[child.signatureParameters.mgf.algorithmOid];
        if(mgf === undefined || forge.mgf[mgf] === undefined) {
          throw {
            message: 'Unsupported MGF function.',
            oid: child.signatureParameters.mgf.algorithmOid,
            name: mgf
          };
        }

        mgf = forge.mgf[mgf].create(forge.md[hash].create());

        /* initialize hash function */
        hash = oids[child.signatureParameters.hash.algorithmOid];
        if(hash === undefined || forge.md[hash] === undefined) {
          throw {
            message: 'Unsupported RSASSA-PSS hash function.',
            oid: child.signatureParameters.hash.algorithmOid,
            name: hash
          };
        }

        scheme = forge.pss.create(forge.md[hash].create(), mgf,
          child.signatureParameters.saltLength);
        break;
      }

      // verify signature on cert using public key
      rval = cert.publicKey.verify(
        md.digest().getBytes(), child.signature, scheme);
    }

    return rval;
  };

  /**
   * Returns true if the passed certificate's subject is the issuer of
   * this certificate.
   *
   * @param parent the certificate to check.
   *
   * @return true if the passed certificate's subject is the issuer of
   *         this certificate.
   */
  cert.isIssuer = function(parent) {
    var rval = false;

    var i = cert.issuer;
    var s = parent.subject;

    // compare hashes if present
    if(i.hash && s.hash) {
      rval = (i.hash === s.hash);
    }
    // if all attributes are the same then issuer matches subject
    else if(i.attributes.length === s.attributes.length) {
      rval = true;
      var iattr, sattr;
      for(var n = 0; rval && n < i.attributes.length; ++n) {
        iattr = i.attributes[n];
        sattr = s.attributes[n];
        if(iattr.type !== sattr.type || iattr.value !== sattr.value) {
          // attribute mismatch
          rval = false;
        }
      }
    }

    return rval;
  };

  /**
   * Generates the subjectKeyIdentifier for this certificate as byte buffer.
   *
   * @return the subjectKeyIdentifier for this certificate as byte buffer.
   */
  cert.generateSubjectKeyIdentifier = function() {
    /* See: 4.2.1.2 section of the the RFC3280, keyIdentifier is either:

      (1) The keyIdentifier is composed of the 160-bit SHA-1 hash of the
        value of the BIT STRING subjectPublicKey (excluding the tag,
        length, and number of unused bits).

      (2) The keyIdentifier is composed of a four bit type field with
        the value 0100 followed by the least significant 60 bits of the
        SHA-1 hash of the value of the BIT STRING subjectPublicKey
        (excluding the tag, length, and number of unused bit string bits).
    */

    // skipping the tag, length, and number of unused bits is the same
    // as just using the RSAPublicKey (for RSA keys, which are the
    // only ones supported)
    var der = asn1.toDer(pki.publicKeyToRSAPublicKey(cert.publicKey));

    // hash public key
    var md = forge.md.sha1.create();
    md.update(der.getBytes());
    return md.digest();
  };

  /**
   * Verifies the subjectKeyIdentifier extension value for this certificate
   * against its public key. If no extension is found, false will be
   * returned.
   *
   * @return true if verified, false if not.
   */
  cert.verifySubjectKeyIdentifier = function() {
    var rval = false;
    var oid = oids['subjectKeyIdentifier'];
    for(var i = 0; i < cert.extensions.length; ++i) {
      var ext = cert.extensions[i];
      if(ext.id === oid) {
        var ski = cert.generateSubjectKeyIdentifier().getBytes();
        return (forge.util.hexToBytes(ext.subjectKeyIdentifier) === ski);
      }
    }
    return false;
  };

  return cert;
};

/**
 * Converts an X.509v3 RSA certificate from an ASN.1 object.
 *
 * Note: If the certificate is to be verified then compute hash should
 * be set to true. There is currently no implementation for converting
 * a certificate back to ASN.1 so the TBSCertificate part of the ASN.1
 * object needs to be scanned before the cert object is created.
 *
 * @param obj the asn1 representation of an X.509v3 RSA certificate.
 * @param computeHash true to compute the hash for verification.
 *
 * @return the certificate.
 */
pki.certificateFromAsn1 = function(obj, computeHash) {
  // validate certificate and capture data
  var capture = {};
  var errors = [];
  if(!asn1.validate(obj, x509CertificateValidator, capture, errors)) {
    throw {
      message: 'Cannot read X.509 certificate. ' +
        'ASN.1 object is not an X509v3 Certificate.',
      errors: errors
    };
  }

  // ensure signature is not interpreted as an embedded ASN.1 object
  if(typeof capture.certSignature !== 'string') {
    var certSignature = '\x00';
    for(var i = 0; i < capture.certSignature.length; ++i) {
      certSignature += asn1.toDer(capture.certSignature[i]).getBytes();
    }
    capture.certSignature = certSignature;
  }

  // get oid
  var oid = asn1.derToOid(capture.publicKeyOid);
  if(oid !== pki.oids['rsaEncryption']) {
    throw {
      message: 'Cannot read public key. OID is not RSA.'
    };
  }

  // create certificate
  var cert = pki.createCertificate();
  cert.version = capture.certVersion ?
    capture.certVersion.charCodeAt(0) : 0;
  var serial = forge.util.createBuffer(capture.certSerialNumber);
  cert.serialNumber = serial.toHex();
  cert.signatureOid = forge.asn1.derToOid(capture.certSignatureOid);
  cert.signatureParameters = _readSignatureParameters(
    cert.signatureOid, capture.certSignatureParams, true);
  cert.siginfo.algorithmOid = forge.asn1.derToOid(capture.certinfoSignatureOid);
  cert.siginfo.parameters = _readSignatureParameters(cert.siginfo.algorithmOid,
    capture.certinfoSignatureParams, false);
  // skip "unused bits" in signature value BITSTRING
  var signature = forge.util.createBuffer(capture.certSignature);
  ++signature.read;
  cert.signature = signature.getBytes();

  var validity = [];
  if(capture.certValidity1UTCTime !== undefined) {
    validity.push(asn1.utcTimeToDate(capture.certValidity1UTCTime));
  }
  if(capture.certValidity2GeneralizedTime !== undefined) {
    validity.push(asn1.generalizedTimeToDate(
      capture.certValidity2GeneralizedTime));
  }
  if(capture.certValidity3UTCTime !== undefined) {
    validity.push(asn1.utcTimeToDate(capture.certValidity3UTCTime));
  }
  if(capture.certValidity4GeneralizedTime !== undefined) {
    validity.push(asn1.generalizedTimeToDate(
      capture.certValidity4GeneralizedTime));
  }
  if(validity.length > 2) {
    throw {
      message: 'Cannot read notBefore/notAfter validity times; more than ' +
        'two times were provided in the certificate.'
    };
  }
  if(validity.length < 2) {
    throw {
      message: 'Cannot read notBefore/notAfter validity times; they were not ' +
        'provided as either UTCTime or GeneralizedTime.'
    };
  }
  cert.validity.notBefore = validity[0];
  cert.validity.notAfter = validity[1];

  // keep TBSCertificate to preserve signature when exporting
  cert.tbsCertificate = capture.tbsCertificate;

  if(computeHash) {
    // check signature OID for supported signature types
    cert.md = null;
    if(cert.signatureOid in oids) {
      var oid = oids[cert.signatureOid];
      switch(oid) {
      case 'sha1WithRSAEncryption':
        cert.md = forge.md.sha1.create();
        break;
      case 'md5WithRSAEncryption':
        cert.md = forge.md.md5.create();
        break;
      case 'sha256WithRSAEncryption':
        cert.md = forge.md.sha256.create();
        break;
      case 'RSASSA-PSS':
        cert.md = forge.md.sha256.create();
        break;
      }
    }
    if(cert.md === null) {
      throw {
        message: 'Could not compute certificate digest. ' +
          'Unknown signature OID.',
        signatureOid: cert.signatureOid
      };
    }

    // produce DER formatted TBSCertificate and digest it
    var bytes = asn1.toDer(cert.tbsCertificate);
    cert.md.update(bytes.getBytes());
  }

  // handle issuer, build issuer message digest
  var imd = forge.md.sha1.create();
  cert.issuer.getField = function(sn) {
    return _getAttribute(cert.issuer, sn);
  };
  cert.issuer.addField = function(attr) {
    _fillMissingFields([attr]);
    cert.issuer.attributes.push(attr);
  };
  cert.issuer.attributes = pki.RDNAttributesAsArray(capture.certIssuer, imd);
  if(capture.certIssuerUniqueId) {
    cert.issuer.uniqueId = capture.certIssuerUniqueId;
  }
  cert.issuer.hash = imd.digest().toHex();

  // handle subject, build subject message digest
  var smd = forge.md.sha1.create();
  cert.subject.getField = function(sn) {
    return _getAttribute(cert.subject, sn);
  };
  cert.subject.addField = function(attr) {
    _fillMissingFields([attr]);
    cert.subject.attributes.push(attr);
  };
  cert.subject.attributes = pki.RDNAttributesAsArray(capture.certSubject, smd);
  if(capture.certSubjectUniqueId) {
    cert.subject.uniqueId = capture.certSubjectUniqueId;
  }
  cert.subject.hash = smd.digest().toHex();

  // handle extensions
  if(capture.certExtensions) {
    cert.extensions = _parseExtensions(capture.certExtensions);
  }
  else {
    cert.extensions = [];
  }

  // convert RSA public key from ASN.1
  cert.publicKey = pki.publicKeyFromAsn1(capture.subjectPublicKeyInfo);

  return cert;
};

/**
 * Converts a PKCS#10 certification request (CSR) from an ASN.1 object.
 *
 * Note: If the certification request is to be verified then compute hash
 * should be set to true. There is currently no implementation for converting
 * a certificate back to ASN.1 so the CertificationRequestInfo part of the
 * ASN.1 object needs to be scanned before the csr object is created.
 *
 * @param obj the asn1 representation of a PKCS#10 certification request (CSR).
 * @param computeHash true to compute the hash for verification.
 *
 * @return the certification request (CSR).
 */
pki.certificationRequestFromAsn1 = function(obj, computeHash) {
  // validate certification request and capture data
  var capture = {};
  var errors = [];
  if(!asn1.validate(obj, certificationRequestValidator, capture, errors)) {
    throw {
      message: 'Cannot read PKCS#10 certificate request. ' +
        'ASN.1 object is not a PKCS#10 CertificationRequest.',
      errors: errors
    };
  }

  // ensure signature is not interpreted as an embedded ASN.1 object
  if(typeof capture.csrSignature !== 'string') {
    var csrSignature = '\x00';
    for(var i = 0; i < capture.csrSignature.length; ++i) {
      csrSignature += asn1.toDer(capture.csrSignature[i]).getBytes();
    }
    capture.csrSignature = csrSignature;
  }

  // get oid
  var oid = asn1.derToOid(capture.publicKeyOid);
  if(oid !== pki.oids['rsaEncryption']) {
    throw {
      message: 'Cannot read public key. OID is not RSA.'
    };
  }

  // create certification request
  var csr = pki.createCertificationRequest();
  csr.version = capture.csrVersion ? capture.csrVersion.charCodeAt(0) : 0;
  csr.signatureOid = forge.asn1.derToOid(capture.csrSignatureOid);
  csr.signatureParameters = _readSignatureParameters(
    csr.signatureOid, capture.csrSignatureParams, true);
  csr.siginfo.algorithmOid = forge.asn1.derToOid(capture.csrSignatureOid);
  csr.siginfo.parameters = _readSignatureParameters(
    csr.siginfo.algorithmOid, capture.csrSignatureParams, false);
  // skip "unused bits" in signature value BITSTRING
  var signature = forge.util.createBuffer(capture.csrSignature);
  ++signature.read;
  csr.signature = signature.getBytes();

  // keep CertificationRequestInfo to preserve signature when exporting
  csr.certificationRequestInfo = capture.certificationRequestInfo;

  if(computeHash) {
    // check signature OID for supported signature types
    csr.md = null;
    if(csr.signatureOid in oids) {
      var oid = oids[csr.signatureOid];
      switch(oid) {
      case 'sha1WithRSAEncryption':
        csr.md = forge.md.sha1.create();
        break;
      case 'md5WithRSAEncryption':
        csr.md = forge.md.md5.create();
        break;
      case 'sha256WithRSAEncryption':
        csr.md = forge.md.sha256.create();
        break;
      case 'RSASSA-PSS':
        csr.md = forge.md.sha256.create();
        break;
      }
    }
    if(csr.md === null) {
      throw {
        message: 'Could not compute certification request digest. ' +
          'Unknown signature OID.',
        signatureOid: csr.signatureOid
      };
    }

    // produce DER formatted CertificationRequestInfo and digest it
    var bytes = asn1.toDer(csr.certificationRequestInfo);
    csr.md.update(bytes.getBytes());
  }

  // handle subject, build subject message digest
  var smd = forge.md.sha1.create();
  csr.subject.getField = function(sn) {
    return _getAttribute(csr.subject, sn);
  };
  csr.subject.addField = function(attr) {
    _fillMissingFields([attr]);
    csr.subject.attributes.push(attr);
  };
  csr.subject.attributes = pki.RDNAttributesAsArray(
    capture.certificationRequestInfoSubject, smd);
  csr.subject.hash = smd.digest().toHex();

  // convert RSA public key from ASN.1
  csr.publicKey = pki.publicKeyFromAsn1(capture.subjectPublicKeyInfo);

  // convert attributes from ASN.1
  csr.getAttribute = function(sn) {
    return _getAttribute(csr.attributes, sn);
  };
  csr.addAttribute = function(attr) {
    _fillMissingFields([attr]);
    csr.attributes.push(attr);
  };
  csr.attributes = pki.CRIAttributesAsArray(
    capture.certificationRequestInfoAttributes);

  return csr;
};

/**
 * Creates an empty certification request (a CSR or certificate signing
 * request). Once created, its public key and attributes can be set and then
 * it can be signed.
 *
 * @return the empty certification request.
 */
pki.createCertificationRequest = function() {
  var csr = {};
  csr.version = 0x00;
  csr.signatureOid = null;
  csr.signature = null;
  csr.siginfo = {};
  csr.siginfo.algorithmOid = null;

  csr.subject = {};
  csr.subject.getField = function(sn) {
    return _getAttribute(csr.subject, sn);
  };
  csr.subject.addField = function(attr) {
    _fillMissingFields([attr]);
    csr.subject.attributes.push(attr);
  };
  csr.subject.attributes = [];
  csr.subject.hash = null;

  csr.publicKey = null;
  csr.attributes = [];
  csr.getAttribute = function(sn) {
    return _getAttribute(csr.attributes, sn);
  };
  csr.addAttribute = function(attr) {
    _fillMissingFields([attr]);
    csr.attributes.push(attr);
  };
  csr.md = null;

  /**
   * Fills in missing fields in attributes.
   *
   * @param attrs the attributes to fill missing fields in.
   */
  var _fillMissingFields = function(attrs) {
    var attr;
    for(var i = 0; i < attrs.length; ++i) {
      attr = attrs[i];

      // populate missing name
      if(typeof(attr.name) === 'undefined') {
        if(attr.type && attr.type in pki.oids) {
          attr.name = pki.oids[attr.type];
        }
        else if(attr.shortName && attr.shortName in _shortNames) {
          attr.name = pki.oids[_shortNames[attr.shortName]];
        }
      }

      // populate missing type (OID)
      if(typeof(attr.type) === 'undefined') {
        if(attr.name && attr.name in pki.oids) {
          attr.type = pki.oids[attr.name];
        }
        else {
          throw {
            message: 'Attribute type not specified.',
            attribute: attr
          };
        }
      }

      // populate missing shortname
      if(typeof(attr.shortName) === 'undefined') {
        if(attr.name && attr.name in _shortNames) {
          attr.shortName = _shortNames[attr.name];
        }
      }

      if(typeof(attr.value) === 'undefined') {
        throw {
          message: 'Attribute value not specified.',
          attribute: attr
        };
      }
    }
  };

  /**
   * Sets the subject of this certification request.
   *
   * @param attrs the array of subject attributes to use.
   */
  csr.setSubject = function(attrs) {
    // set new attributes
    _fillMissingFields(attrs);
    csr.subject.attributes = attrs;
    csr.subject.hash = null;
  };

  /**
   * Sets the attributes of this certification request.
   *
   * @param attrs the array of attributes to use.
   */
  csr.setAttributes = function(attrs) {
    // set new attributes
    _fillMissingFields(attrs);
    csr.attributes = attrs;
  };

  /**
   * Signs this certification request using the given private key.
   *
   * @param key the private key to sign with.
   * @param md the message digest object to use (defaults to forge.md.sha1).
   */
  csr.sign = function(key, md) {
    // TODO: get signature OID from private key
    csr.md = md || forge.md.sha1.create();
    var algorithmOid = oids[csr.md.algorithm + 'WithRSAEncryption'];
    if(!algorithmOid) {
      throw {
        message: 'Could not compute certification request digest. ' +
          'Unknown message digest algorithm OID.',
        algorithm: csr.md.algorithm
      };
    }
    csr.signatureOid = csr.siginfo.algorithmOid = algorithmOid;

    // get CertificationRequestInfo, convert to DER
    csr.certificationRequestInfo = pki.getCertificationRequestInfo(csr);
    var bytes = asn1.toDer(csr.certificationRequestInfo);

    // digest and sign
    csr.md.update(bytes.getBytes());
    csr.signature = key.sign(csr.md);
  };

  /**
   * Attempts verify the signature on the passed certification request using
   * its public key.
   *
   * A CSR that has been exported to a file in PEM format can be verified using
   * OpenSSL using this command:
   *
   * openssl req -in <the-csr-pem-file> -verify -noout -text
   *
   * @return true if verified, false if not.
   */
  csr.verify = function() {
    var rval = false;

    var md = csr.md;
    if(md === null) {
      // check signature OID for supported signature types
      if(csr.signatureOid in oids) {
        var oid = oids[csr.signatureOid];
        switch(oid) {
        case 'sha1withRSAEncryption':
          md = forge.md.sha1.create();
          break;
        case 'md5withRSAEncryption':
          md = forge.md.md5.create();
          break;
        case 'sha256WithRSAEncryption':
          md = forge.md.sha256.create();
          break;
        case 'RSASSA-PSS':
          md = forge.md.sha256.create();
          break;
        }
      }
      if(md === null) {
        throw {
          message: 'Could not compute certification request digest. ' +
            'Unknown signature OID.',
          signatureOid: csr.signatureOid
        };
      }

      // produce DER formatted CertificationRequestInfo and digest it
      var cri = csr.certificationRequestInfo ||
        pki.getCertificationRequestInfo(csr);
      var bytes = asn1.toDer(cri);
      md.update(bytes.getBytes());
    }

    if(md !== null) {
      var scheme = undefined;

      switch(csr.signatureOid) {
      case oids['sha1withRSAEncryption']:
        scheme = undefined;  /* use PKCS#1 v1.5 padding scheme */
        break;
      case oids['RSASSA-PSS']:
        var hash, mgf;

        /* initialize mgf */
        hash = oids[csr.signatureParameters.mgf.hash.algorithmOid];
        if(hash === undefined || forge.md[hash] === undefined) {
          throw {
            message: 'Unsupported MGF hash function.',
            oid: csr.signatureParameters.mgf.hash.algorithmOid,
            name: hash
          };
        }

        mgf = oids[csr.signatureParameters.mgf.algorithmOid];
        if(mgf === undefined || forge.mgf[mgf] === undefined) {
          throw {
            message: 'Unsupported MGF function.',
            oid: csr.signatureParameters.mgf.algorithmOid,
            name: mgf
          };
        }

        mgf = forge.mgf[mgf].create(forge.md[hash].create());

        /* initialize hash function */
        hash = oids[csr.signatureParameters.hash.algorithmOid];
        if(hash === undefined || forge.md[hash] === undefined) {
          throw {
            message: 'Unsupported RSASSA-PSS hash function.',
            oid: csr.signatureParameters.hash.algorithmOid,
            name: hash
          };
        }

        scheme = forge.pss.create(forge.md[hash].create(), mgf,
          csr.signatureParameters.saltLength);
        break;
      }

      // verify signature on csr using its public key
      rval = csr.publicKey.verify(
        md.digest().getBytes(), csr.signature, scheme);
    }

    return rval;
  };

  return csr;
};

/**
 * Converts an X.509 subject or issuer to an ASN.1 RDNSequence.
 *
 * @param obj the subject or issuer (distinguished name).
 *
 * @return the ASN.1 RDNSequence.
 */
function _dnToAsn1(obj) {
  // create an empty RDNSequence
  var rval = asn1.create(
    asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, []);

  // iterate over attributes
  var attr, set;
  var attrs = obj.attributes;
  for(var i = 0; i < attrs.length; ++i) {
    attr = attrs[i];
    var value = attr.value;

    // reuse tag class for attribute value if available
    var valueTagClass = asn1.Type.PRINTABLESTRING;
    if('valueTagClass' in attr) {
      valueTagClass = attr.valueTagClass;

      if(valueTagClass === asn1.Type.UTF8) {
        value = forge.util.encodeUtf8(value);
      }
      // FIXME: handle more encodings
    }

    // create a RelativeDistinguishedName set
    // each value in the set is an AttributeTypeAndValue first
    // containing the type (an OID) and second the value
    set = asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SET, true, [
      asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [
        // AttributeType
        asn1.create(asn1.Class.UNIVERSAL, asn1.Type.OID, false,
          asn1.oidToDer(attr.type).getBytes()),
        // AttributeValue
        asn1.create(asn1.Class.UNIVERSAL, valueTagClass, false, value)
      ])
    ]);
    rval.value.push(set);
  }

  return rval;
}

/**
 * Converts X.509v3 certificate extensions to ASN.1.
 *
 * @param exts the extensions to convert.
 *
 * @return the extensions in ASN.1 format.
 */
function _extensionsToAsn1(exts) {
  // create top-level extension container
  var rval = asn1.create(asn1.Class.CONTEXT_SPECIFIC, 3, true, []);

  // create extension sequence (stores a sequence for each extension)
  var seq = asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, []);
  rval.value.push(seq);

  var ext, extseq;
  for(var i = 0; i < exts.length; ++i) {
    ext = exts[i];

    // create a sequence for each extension
    extseq = asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, []);
    seq.value.push(extseq);

    // extnID (OID)
    extseq.value.push(asn1.create(
      asn1.Class.UNIVERSAL, asn1.Type.OID, false,
      asn1.oidToDer(ext.id).getBytes()));

    // critical defaults to false
    if(ext.critical) {
      // critical BOOLEAN DEFAULT FALSE
      extseq.value.push(asn1.create(
        asn1.Class.UNIVERSAL, asn1.Type.BOOLEAN, false,
        String.fromCharCode(0xFF)));
    }

    var value = ext.value;
    if(typeof ext.value !== 'string') {
      // value is asn.1
      value = asn1.toDer(value).getBytes();
    }

    // extnValue (OCTET STRING)
    extseq.value.push(asn1.create(
      asn1.Class.UNIVERSAL, asn1.Type.OCTETSTRING, false, value));
  }

  return rval;
}

/**
 * Convert signature parameters object to ASN.1
 *
 * @param {String} oid Signature algorithm OID
 * @param params The signature parametrs object
 * @return ASN.1 object representing signature parameters
 */
function _signatureParametersToAsn1(oid, params) {
  switch(oid) {
  case oids['RSASSA-PSS']:
    var parts = [];

    if(params.hash.algorithmOid !== undefined) {
      parts.push(asn1.create(asn1.Class.CONTEXT_SPECIFIC, 0, true, [
        asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [
          asn1.create(asn1.Class.UNIVERSAL, asn1.Type.OID, false,
            asn1.oidToDer(params.hash.algorithmOid).getBytes()),
          asn1.create(asn1.Class.UNIVERSAL, asn1.Type.NULL, false, '')
        ])
      ]));
    }

    if(params.mgf.algorithmOid !== undefined) {
      parts.push(asn1.create(asn1.Class.CONTEXT_SPECIFIC, 1, true, [
        asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [
          asn1.create(asn1.Class.UNIVERSAL, asn1.Type.OID, false,
            asn1.oidToDer(params.mgf.algorithmOid).getBytes()),
          asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [
            asn1.create(asn1.Class.UNIVERSAL, asn1.Type.OID, false,
              asn1.oidToDer(params.mgf.hash.algorithmOid).getBytes()),
            asn1.create(asn1.Class.UNIVERSAL, asn1.Type.NULL, false, '')
          ])
        ])
      ]));
    }

    if(params.saltLength !== undefined) {
      parts.push(asn1.create(asn1.Class.CONTEXT_SPECIFIC, 2, true, [
        asn1.create(asn1.Class.UNIVERSAL, asn1.Type.INTEGER, false,
          String.fromCharCode(params.saltLength))
      ]));
    }

    return asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, parts);

  default:
    return asn1.create(asn1.Class.UNIVERSAL, asn1.Type.NULL, false, '');
  }
}

/**
 * Converts a certification request's attributes to an ASN.1 set of
 * CRIAttributes.
 *
 * @param csr certification request.
 *
 * @return the ASN.1 set of CRIAttributes.
 */
function _CRIAttributesToAsn1(csr) {
  // create an empty context-specific container
  var rval = asn1.create(asn1.Class.CONTEXT_SPECIFIC, 0, true, []);

  // no attributes, return empty container
  if(csr.attributes.length === 0) {
    return rval;
  }

  // each attribute has a sequence with a type and a set of values
  var attrs = csr.attributes;
  for(var i = 0; i < attrs.length; ++i) {
    var attr = attrs[i];
    var value = attr.value;

    // reuse tag class for attribute value if available
    var valueTagClass = asn1.Type.UTF8;
    if('valueTagClass' in attr) {
      valueTagClass = attr.valueTagClass;
    }
    if(valueTagClass === asn1.Type.UTF8) {
      value = forge.util.encodeUtf8(value);
    }
    // FIXME: handle more encodings

    // create a RelativeDistinguishedName set
    // each value in the set is an AttributeTypeAndValue first
    // containing the type (an OID) and second the value
    var seq = asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [
      // AttributeType
      asn1.create(asn1.Class.UNIVERSAL, asn1.Type.OID, false,
        asn1.oidToDer(attr.type).getBytes()),
      asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SET, true, [
        // AttributeValue
        asn1.create(asn1.Class.UNIVERSAL, valueTagClass, false, value)
      ])
    ]);
    rval.value.push(seq);
  }

  return rval;
}

/**
 * Gets the ASN.1 TBSCertificate part of an X.509v3 certificate.
 *
 * @param cert the certificate.
 *
 * @return the asn1 TBSCertificate.
 */
pki.getTBSCertificate = function(cert) {
  // TBSCertificate
  var tbs = asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [
    // version
    asn1.create(asn1.Class.CONTEXT_SPECIFIC, 0, true, [
      // integer
      asn1.create(asn1.Class.UNIVERSAL, asn1.Type.INTEGER, false,
        String.fromCharCode(cert.version))
    ]),
    // serialNumber
    asn1.create(asn1.Class.UNIVERSAL, asn1.Type.INTEGER, false,
      forge.util.hexToBytes(cert.serialNumber)),
    // signature
    asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [
      // algorithm
      asn1.create(asn1.Class.UNIVERSAL, asn1.Type.OID, false,
        asn1.oidToDer(cert.siginfo.algorithmOid).getBytes()),
      // parameters
      _signatureParametersToAsn1(
        cert.siginfo.algorithmOid, cert.siginfo.parameters)
    ]),
    // issuer
    _dnToAsn1(cert.issuer),
    // validity
    asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [
      // notBefore
      asn1.create(asn1.Class.UNIVERSAL, asn1.Type.UTCTIME, false,
        asn1.dateToUtcTime(cert.validity.notBefore)),
      // notAfter
      asn1.create(asn1.Class.UNIVERSAL, asn1.Type.UTCTIME, false,
        asn1.dateToUtcTime(cert.validity.notAfter))
    ]),
    // subject
    _dnToAsn1(cert.subject),
    // SubjectPublicKeyInfo
    pki.publicKeyToAsn1(cert.publicKey)
  ]);

  if(cert.issuer.uniqueId) {
    // issuerUniqueID (optional)
    tbs.value.push(
      asn1.create(asn1.Class.CONTEXT_SPECIFIC, 1, true, [
        asn1.create(asn1.Class.UNIVERSAL, asn1.Type.BITSTRING, false,
          String.fromCharCode(0x00) +
          cert.issuer.uniqueId
        )
      ])
    );
  }
  if(cert.subject.uniqueId) {
    // subjectUniqueID (optional)
    tbs.value.push(
      asn1.create(asn1.Class.CONTEXT_SPECIFIC, 2, true, [
        asn1.create(asn1.Class.UNIVERSAL, asn1.Type.BITSTRING, false,
          String.fromCharCode(0x00) +
          cert.subject.uniqueId
        )
      ])
    );
  }

  if(cert.extensions.length > 0) {
    // extensions (optional)
    tbs.value.push(_extensionsToAsn1(cert.extensions));
  }

  return tbs;
};

/**
 * Gets the ASN.1 CertificationRequestInfo part of a
 * PKCS#10 CertificationRequest.
 *
 * @param csr the certification request.
 *
 * @return the asn1 CertificationRequestInfo.
 */
pki.getCertificationRequestInfo = function(csr) {
  // CertificationRequestInfo
  var cri = asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [
    // version
    asn1.create(asn1.Class.UNIVERSAL, asn1.Type.INTEGER, false,
      String.fromCharCode(csr.version)),
    // subject
    _dnToAsn1(csr.subject),
    // SubjectPublicKeyInfo
    pki.publicKeyToAsn1(csr.publicKey),
    // attributes
    _CRIAttributesToAsn1(csr)
  ]);

  return cri;
};

/**
 * Converts a DistinguishedName (subject or issuer) to an ASN.1 object.
 *
 * @param dn the DistinguishedName.
 *
 * @return the asn1 representation of a DistinguishedName.
 */
pki.distinguishedNameToAsn1 = function(dn) {
  return _dnToAsn1(dn);
};

/**
 * Converts an X.509v3 RSA certificate to an ASN.1 object.
 *
 * @param cert the certificate.
 *
 * @return the asn1 representation of an X.509v3 RSA certificate.
 */
pki.certificateToAsn1 = function(cert) {
  // prefer cached TBSCertificate over generating one
  var tbsCertificate = cert.tbsCertificate || pki.getTBSCertificate(cert);

  // Certificate
  return asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [
    // TBSCertificate
    tbsCertificate,
    // AlgorithmIdentifier (signature algorithm)
    asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [
      // algorithm
      asn1.create(asn1.Class.UNIVERSAL, asn1.Type.OID, false,
        asn1.oidToDer(cert.signatureOid).getBytes()),
      // parameters
      _signatureParametersToAsn1(cert.signatureOid, cert.signatureParameters)
    ]),
    // SignatureValue
    asn1.create(asn1.Class.UNIVERSAL, asn1.Type.BITSTRING, false,
      String.fromCharCode(0x00) + cert.signature)
  ]);
};

/**
 * Converts a PKCS#10 certification request to an ASN.1 object.
 *
 * @param csr the certification request.
 *
 * @return the asn1 representation of a certification request.
 */
pki.certificationRequestToAsn1 = function(csr) {
  // prefer cached CertificationRequestInfo over generating one
  var cri = csr.certificationRequestInfo ||
    pki.getCertificationRequestInfo(csr);

  // Certificate
  return asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [
    // CertificationRequestInfo
    cri,
    // AlgorithmIdentifier (signature algorithm)
    asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [
      // algorithm
      asn1.create(asn1.Class.UNIVERSAL, asn1.Type.OID, false,
        asn1.oidToDer(csr.signatureOid).getBytes()),
      // parameters
      _signatureParametersToAsn1(csr.signatureOid, csr.signatureParameters)
    ]),
    // signature
    asn1.create(asn1.Class.UNIVERSAL, asn1.Type.BITSTRING, false,
      String.fromCharCode(0x00) + csr.signature)
  ]);
};

/**
 * Creates a CA store.
 *
 * @param certs an optional array of certificate objects or PEM-formatted
 *          certificate strings to add to the CA store.
 *
 * @return the CA store.
 */
pki.createCaStore = function(certs) {
  // create CA store
  var caStore = {
    // stored certificates
    certs: {}
  };

  /**
   * Gets the certificate that issued the passed certificate or its
   * 'parent'.
   *
   * @param cert the certificate to get the parent for.
   *
   * @return the parent certificate or null if none was found.
   */
  caStore.getIssuer = function(cert) {
    var rval = null;

    // produce issuer hash if it doesn't exist
    if(!cert.issuer.hash) {
      var md = forge.md.sha1.create();
      cert.issuer.attributes =  pki.RDNAttributesAsArray(
        _dnToAsn1(cert.issuer), md);
      cert.issuer.hash = md.digest().toHex();
    }

    // get the entry using the cert's issuer hash
    if(cert.issuer.hash in caStore.certs) {
      rval = caStore.certs[cert.issuer.hash];

      // see if there are multiple matches
      if(forge.util.isArray(rval)) {
        // TODO: resolve multiple matches by checking
        // authorityKey/subjectKey/issuerUniqueID/other identifiers, etc.
        // FIXME: or alternatively do authority key mapping
        // if possible (X.509v1 certs can't work?)
        throw {
          message: 'Resolving multiple issuer matches not implemented yet.'
        };
      }
    }

    return rval;
  };

  /**
   * Adds a trusted certificate to the store.
   *
   * @param cert the certificate to add as a trusted certificate (either a
   *          pki.certificate object or a PEM-formatted certificate).
   */
  caStore.addCertificate = function(cert) {
    // convert from pem if necessary
    if(typeof cert === 'string') {
      cert = forge.pki.certificateFromPem(cert);
    }

    // produce subject hash if it doesn't exist
    if(!cert.subject.hash) {
      var md = forge.md.sha1.create();
      cert.subject.attributes =  pki.RDNAttributesAsArray(
        _dnToAsn1(cert.subject), md);
      cert.subject.hash = md.digest().toHex();
    }

    if(cert.subject.hash in caStore.certs) {
      // subject hash already exists, append to array
      var tmp = caStore.certs[cert.subject.hash];
      if(!forge.util.isArray(tmp)) {
        tmp = [tmp];
      }
      tmp.push(cert);
    }
    else {
      caStore.certs[cert.subject.hash] = cert;
    }
  };

  // auto-add passed in certs
  if(certs) {
    // parse PEM-formatted certificates as necessary
    for(var i = 0; i < certs.length; ++i) {
      var cert = certs[i];
      caStore.addCertificate(cert);
    }
  }

  return caStore;
};

/**
 * Certificate verification errors, based on TLS.
 */
pki.certificateError = {
  bad_certificate: 'forge.pki.BadCertificate',
  unsupported_certificate: 'forge.pki.UnsupportedCertificate',
  certificate_revoked: 'forge.pki.CertificateRevoked',
  certificate_expired: 'forge.pki.CertificateExpired',
  certificate_unknown: 'forge.pki.CertificateUnknown',
  unknown_ca: 'forge.pki.UnknownCertificateAuthority'
};

/**
 * Verifies a certificate chain against the given Certificate Authority store
 * with an optional custom verify callback.
 *
 * @param caStore a certificate store to verify against.
 * @param chain the certificate chain to verify, with the root or highest
 *          authority at the end (an array of certificates).
 * @param verify called for every certificate in the chain.
 *
 * The verify callback has the following signature:
 *
 * verified - Set to true if certificate was verified, otherwise the
 *   pki.certificateError for why the certificate failed.
 * depth - The current index in the chain, where 0 is the end point's cert.
 * certs - The certificate chain, *NOTE* an empty chain indicates an anonymous
 *   end point.
 *
 * The function returns true on success and on failure either the appropriate
 * pki.certificateError or an object with 'error' set to the appropriate
 * pki.certificateError and 'message' set to a custom error message.
 *
 * @return true if successful, error thrown if not.
 */
pki.verifyCertificateChain = function(caStore, chain, verify) {
  /* From: RFC3280 - Internet X.509 Public Key Infrastructure Certificate
    Section 6: Certification Path Validation
    See inline parentheticals related to this particular implementation.

    The primary goal of path validation is to verify the binding between
    a subject distinguished name or a subject alternative name and subject
    public key, as represented in the end entity certificate, based on the
    public key of the trust anchor. This requires obtaining a sequence of
    certificates that support that binding. That sequence should be provided
    in the passed 'chain'. The trust anchor should be in the given CA
    store. The 'end entity' certificate is the certificate provided by the
    end point (typically a server) and is the first in the chain.

    To meet this goal, the path validation process verifies, among other
    things, that a prospective certification path (a sequence of n
    certificates or a 'chain') satisfies the following conditions:

    (a) for all x in {1, ..., n-1}, the subject of certificate x is
          the issuer of certificate x+1;

    (b) certificate 1 is issued by the trust anchor;

    (c) certificate n is the certificate to be validated; and

    (d) for all x in {1, ..., n}, the certificate was valid at the
          time in question.

    Note that here 'n' is index 0 in the chain and 1 is the last certificate
    in the chain and it must be signed by a certificate in the connection's
    CA store.

    The path validation process also determines the set of certificate
    policies that are valid for this path, based on the certificate policies
    extension, policy mapping extension, policy constraints extension, and
    inhibit any-policy extension.

    Note: Policy mapping extension not supported (Not Required).

    Note: If the certificate has an unsupported critical extension, then it
    must be rejected.

    Note: A certificate is self-issued if the DNs that appear in the subject
    and issuer fields are identical and are not empty.

    The path validation algorithm assumes the following seven inputs are
    provided to the path processing logic. What this specific implementation
    will use is provided parenthetically:

    (a) a prospective certification path of length n (the 'chain')
    (b) the current date/time: ('now').
    (c) user-initial-policy-set: A set of certificate policy identifiers
          naming the policies that are acceptable to the certificate user.
          The user-initial-policy-set contains the special value any-policy
          if the user is not concerned about certificate policy
          (Not implemented. Any policy is accepted).
    (d) trust anchor information, describing a CA that serves as a trust
          anchor for the certification path. The trust anchor information
          includes:

      (1)  the trusted issuer name,
      (2)  the trusted public key algorithm,
      (3)  the trusted public key, and
      (4)  optionally, the trusted public key parameters associated
             with the public key.

      (Trust anchors are provided via certificates in the CA store).

      The trust anchor information may be provided to the path processing
      procedure in the form of a self-signed certificate. The trusted anchor
      information is trusted because it was delivered to the path processing
      procedure by some trustworthy out-of-band procedure. If the trusted
      public key algorithm requires parameters, then the parameters are
      provided along with the trusted public key (No parameters used in this
      implementation).

    (e) initial-policy-mapping-inhibit, which indicates if policy mapping is
          allowed in the certification path.
          (Not implemented, no policy checking)

    (f) initial-explicit-policy, which indicates if the path must be valid
          for at least one of the certificate policies in the user-initial-
          policy-set.
          (Not implemented, no policy checking)

    (g) initial-any-policy-inhibit, which indicates whether the
          anyPolicy OID should be processed if it is included in a
          certificate.
          (Not implemented, so any policy is valid provided that it is
          not marked as critical) */

  /* Basic Path Processing:

    For each certificate in the 'chain', the following is checked:

    1. The certificate validity period includes the current time.
    2. The certificate was signed by its parent (where the parent is
       either the next in the chain or from the CA store).
    3. TODO: The certificate has not been revoked.
    4. The certificate issuer name matches the parent's subject name.
    5. TODO: If the certificate is self-issued and not the final certificate
       in the chain, skip this step, otherwise verify that the subject name
       is within one of the permitted subtrees of X.500 distinguished names
       and that each of the alternative names in the subjectAltName extension
       (critical or non-critical) is within one of the permitted subtrees for
       that name type.
    6. TODO: If the certificate is self-issued and not the final certificate
       in the chain, skip this step, otherwise verify that the subject name
       is not within one of the excluded subtrees for X.500 distinguished
       names and none of the subjectAltName extension names are excluded for
       that name type.
    7. The other steps in the algorithm for basic path processing involve
       handling the policy extension which is not presently supported in this
       implementation. Instead, if a critical policy extension is found, the
       certificate is rejected as not supported.
    8. If the certificate is not the first or the only certificate in the
       chain and it has a critical key usage extension, verify that the
       keyCertSign bit is set. If the key usage extension exists, verify that
       the basic constraints extension exists. If the basic constraints
       extension exists, verify that the cA flag is set.
       TODO: handle pathLenConstraint by setting max path length to a lower
       number if the parent certificate's pathLenConstraint is lower. Also
       ensure that the path isn't already too long. */

  // copy cert chain references to another array to protect against changes
  // in verify callback
  chain = chain.slice(0);
  var certs = chain.slice(0);

  // get current date
  var now = new Date();

  // verify each cert in the chain using its parent, where the parent
  // is either the next in the chain or from the CA store
  var first = true;
  var error = null;
  var depth = 0;
  var parent = null;
  do {
    var cert = chain.shift();

    // 1. check valid time
    if(now < cert.validity.notBefore || now > cert.validity.notAfter) {
      error = {
        message: 'Certificate is not valid yet or has expired.',
        error: pki.certificateError.certificate_expired,
        notBefore: cert.validity.notBefore,
        notAfter: cert.validity.notAfter,
        now: now
      };
    }
    // 2. verify with parent
    else {
      // get parent from chain
      var verified = false;
      if(chain.length > 0) {
        // verify using parent
        parent = chain[0];
        try {
          verified = parent.verify(cert);
        }
        catch(ex) {
          // failure to verify, don't care why, just fail
        }
      }
      // get parent(s) from CA store
      else {
        var parents = caStore.getIssuer(cert);
        if(parents === null) {
          // no parent issuer, so certificate not trusted
          error = {
            message: 'Certificate is not trusted.',
            error: pki.certificateError.unknown_ca
          };
        }
        else {
          // CA store might have multiple certificates where the issuer
          // can't be determined from the certificate (unlikely case for
          // old certificates) so normalize by always putting parents into
          // an array
          if(!forge.util.isArray(parents)) {
            parents = [parents];
          }

          // multiple parents to try verifying with
          while(!verified && parents.length > 0) {
            parent = parents.shift();
            try {
              verified = parent.verify(cert);
            }
            catch(ex) {
              // failure to verify, try next one
            }
          }
        }
      }
      if(error === null && !verified) {
        error = {
          message: 'Certificate signature is invalid.',
          error: pki.certificateError.bad_certificate
        };
      }
    }

    // TODO: 3. check revoked

    // 4. check for matching issuer/subject
    if(error === null && !cert.isIssuer(parent)) {
      // parent is not issuer
      error = {
        message: 'Certificate issuer is invalid.',
        error: pki.certificateError.bad_certificate
      };
    }

    // 5. TODO: check names with permitted names tree

    // 6. TODO: check names against excluded names tree

    // 7. check for unsupported critical extensions
    if(error === null) {
      // supported extensions
      var se = {
        keyUsage: true,
        basicConstraints: true
      };
      for(var i = 0; error === null && i < cert.extensions.length; ++i) {
        var ext = cert.extensions[i];
        if(ext.critical && !(ext.name in se)) {
          error = {
            message:
              'Certificate has an unsupported critical extension.',
            error: pki.certificateError.unsupported_certificate
          };
        }
      }
    }

    // 8. check for CA if cert is not first or is the only certificate
    // in chain with no parent, first check keyUsage extension and then basic
    // constraints
    if(!first || (chain.length === 0 && !parent)) {
      var bcExt = cert.getExtension('basicConstraints');
      var keyUsageExt = cert.getExtension('keyUsage');
      if(keyUsageExt !== null) {
        // keyCertSign must be true and there must be a basic
        // constraints extension
        if(!keyUsageExt.keyCertSign || bcExt === null) {
          // bad certificate
          error = {
            message:
              'Certificate keyUsage or basicConstraints conflict ' +
              'or indicate that the certificate is not a CA. ' +
              'If the certificate is the only one in the chain or ' +
              'isn\'t the first then the certificate must be a ' +
              'valid CA.',
            error: pki.certificateError.bad_certificate
          };
        }
      }
      // basic constraints cA flag must be set
      if(error === null && bcExt !== null && !bcExt.cA) {
        // bad certificate
        error = {
          message:
            'Certificate basicConstraints indicates the certificate ' +
            'is not a CA.',
          error: pki.certificateError.bad_certificate
        };
      }
    }

    // call application callback
    var vfd = (error === null) ? true : error.error;
    var ret = verify ? verify(vfd, depth, certs) : vfd;
    if(ret === true) {
      // clear any set error
      error = null;
    }
    else {
      // if passed basic tests, set default message and alert
      if(vfd === true) {
        error = {
          message: 'The application rejected the certificate.',
          error: pki.certificateError.bad_certificate
        };
      }

      // check for custom error info
      if(ret || ret === 0) {
        // set custom message and error
        if(typeof ret === 'object' && !forge.util.isArray(ret)) {
          if(ret.message) {
             error.message = ret.message;
          }
          if(ret.error) {
            error.error = ret.error;
          }
        }
        else if(typeof ret === 'string') {
          // set custom error
          error.error = ret;
        }
      }

      // throw error
      throw error;
    }

    // no longer first cert in chain
    first = false;
    ++depth;
  }
  while(chain.length > 0);

  return true;
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
    // get oid
    var oid = asn1.derToOid(capture.publicKeyOid);
    if(oid !== pki.oids['rsaEncryption']) {
      throw {
        message: 'Cannot read public key. Unknown OID.',
        oid: oid
      };
    }
    obj = capture.rsaPublicKey;
  }

  // get RSA params
  errors = [];
  if(!asn1.validate(obj, rsaPublicKeyValidator, capture, errors)) {
    throw {
      message: 'Cannot read public key. ' +
        'ASN.1 object does not contain an RSAPublicKey.',
      errors: errors
    };
  }

  // FIXME: inefficient, get a BigInteger that uses byte strings
  var n = forge.util.createBuffer(capture.publicKeyModulus).toHex();
  var e = forge.util.createBuffer(capture.publicKeyExponent).toHex();

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
        asn1.oidToDer(pki.oids['rsaEncryption']).getBytes()),
      // parameters (null)
      asn1.create(asn1.Class.UNIVERSAL, asn1.Type.NULL, false, '')
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
      _bnToBytes(key.n)),
    // publicExponent (e)
    asn1.create(asn1.Class.UNIVERSAL, asn1.Type.INTEGER, false,
      _bnToBytes(key.e))
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
    obj = asn1.fromDer(forge.util.createBuffer(capture.privateKey));
  }

  // get RSAPrivateKey
  capture = {};
  errors = [];
  if(!asn1.validate(obj, rsaPrivateKeyValidator, capture, errors)) {
    throw {
      message: 'Cannot read private key. ' +
        'ASN.1 object does not contain an RSAPrivateKey.',
      errors: errors
    };
  }

  // Note: Version is currently ignored.
  // capture.privateKeyVersion
  // FIXME: inefficient, get a BigInteger that uses byte strings
  var n, e, d, p, q, dP, dQ, qInv;
  n = forge.util.createBuffer(capture.privateKeyModulus).toHex();
  e = forge.util.createBuffer(capture.privateKeyPublicExponent).toHex();
  d = forge.util.createBuffer(capture.privateKeyPrivateExponent).toHex();
  p = forge.util.createBuffer(capture.privateKeyPrime1).toHex();
  q = forge.util.createBuffer(capture.privateKeyPrime2).toHex();
  dP = forge.util.createBuffer(capture.privateKeyExponent1).toHex();
  dQ = forge.util.createBuffer(capture.privateKeyExponent2).toHex();
  qInv = forge.util.createBuffer(capture.privateKeyCoefficient).toHex();

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
    asn1.create(asn1.Class.UNIVERSAL, asn1.Type.INTEGER, false,
      String.fromCharCode(0x00)),
    // modulus (n)
    asn1.create(asn1.Class.UNIVERSAL, asn1.Type.INTEGER, false,
      _bnToBytes(key.n)),
    // publicExponent (e)
    asn1.create(asn1.Class.UNIVERSAL, asn1.Type.INTEGER, false,
      _bnToBytes(key.e)),
    // privateExponent (d)
    asn1.create(asn1.Class.UNIVERSAL, asn1.Type.INTEGER, false,
      _bnToBytes(key.d)),
    // privateKeyPrime1 (p)
    asn1.create(asn1.Class.UNIVERSAL, asn1.Type.INTEGER, false,
      _bnToBytes(key.p)),
    // privateKeyPrime2 (q)
    asn1.create(asn1.Class.UNIVERSAL, asn1.Type.INTEGER, false,
      _bnToBytes(key.q)),
    // privateKeyExponent1 (dP)
    asn1.create(asn1.Class.UNIVERSAL, asn1.Type.INTEGER, false,
      _bnToBytes(key.dP)),
    // privateKeyExponent2 (dQ)
    asn1.create(asn1.Class.UNIVERSAL, asn1.Type.INTEGER, false,
      _bnToBytes(key.dQ)),
    // coefficient (qInv)
    asn1.create(asn1.Class.UNIVERSAL, asn1.Type.INTEGER, false,
      _bnToBytes(key.qInv))
  ]);
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
    asn1.create(asn1.Class.UNIVERSAL, asn1.Type.INTEGER, false, '\x00'),
    // privateKeyAlgorithm
    asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [
      asn1.create(
        asn1.Class.UNIVERSAL, asn1.Type.OID, false,
        asn1.oidToDer(oids['rsaEncryption']).getBytes()),
      asn1.create(asn1.Class.UNIVERSAL, asn1.Type.NULL, false, '')
    ]),
    // PrivateKey
    asn1.create(asn1.Class.UNIVERSAL, asn1.Type.OCTETSTRING, false,
      asn1.toDer(rsaKey).getBytes())
    ]);
};

/**
 * Encrypts a ASN.1 PrivateKeyInfo object, producing an EncryptedPrivateKeyInfo.
 *
 * PBES2Algorithms ALGORITHM-IDENTIFIER ::=
 *   { {PBES2-params IDENTIFIED BY id-PBES2}, ...}
 *
 * id-PBES2 OBJECT IDENTIFIER ::= {pkcs-5 13}
 *
 * PBES2-params ::= SEQUENCE {
 *   keyDerivationFunc AlgorithmIdentifier {{PBES2-KDFs}},
 *   encryptionScheme AlgorithmIdentifier {{PBES2-Encs}}
 * }
 *
 * PBES2-KDFs ALGORITHM-IDENTIFIER ::=
 *   { {PBKDF2-params IDENTIFIED BY id-PBKDF2}, ... }
 *
 * PBES2-Encs ALGORITHM-IDENTIFIER ::= { ... }
 *
 * PBKDF2-params ::= SEQUENCE {
 *   salt CHOICE {
 *     specified OCTET STRING,
 *     otherSource AlgorithmIdentifier {{PBKDF2-SaltSources}}
 *   },
 *   iterationCount INTEGER (1..MAX),
 *   keyLength INTEGER (1..MAX) OPTIONAL,
 *   prf AlgorithmIdentifier {{PBKDF2-PRFs}} DEFAULT algid-hmacWithSHA1
 * }
 *
 * @param obj the ASN.1 PrivateKeyInfo object.
 * @param password the password to encrypt with.
 * @param options:
 *          algorithm the encryption algorithm to use
 *            ('aes128', 'aes192', 'aes256', '3des'), defaults to 'aes128'.
 *          count the iteration count to use.
 *          saltSize the salt size to use.
 *
 * @return the ASN.1 EncryptedPrivateKeyInfo.
 */
pki.encryptPrivateKeyInfo = function(obj, password, options) {
  // set default options
  options = options || {};
  options.saltSize = options.saltSize || 8;
  options.count = options.count || 2048;
  options.algorithm = options.algorithm || 'aes128';

  // generate PBE params
  var salt = forge.random.getBytes(options.saltSize);
  var count = options.count;
  var countBytes = forge.util.createBuffer();
  countBytes.putInt16(count);
  var dkLen;
  var encryptionAlgorithm;
  var encryptedData;
  if(options.algorithm.indexOf('aes') === 0) {
    // Do PBES2
    var encOid;
    if(options.algorithm === 'aes128') {
      dkLen = 16;
      encOid = oids['aes128-CBC'];
    }
    else if(options.algorithm === 'aes192') {
      dkLen = 24;
      encOid = oids['aes192-CBC'];
    }
    else if(options.algorithm === 'aes256') {
      dkLen = 32;
      encOid = oids['aes256-CBC'];
    }
    else {
      throw {
        message: 'Cannot encrypt private key. Unknown encryption algorithm.',
        algorithm: options.algorithm
      };
    }

    // encrypt private key using pbe SHA-1 and AES
    var dk = forge.pkcs5.pbkdf2(password, salt, count, dkLen);
    var iv = forge.random.getBytes(16);
    var cipher = forge.aes.createEncryptionCipher(dk);
    cipher.start(iv);
    cipher.update(asn1.toDer(obj));
    cipher.finish();
    encryptedData = cipher.output.getBytes();

    encryptionAlgorithm = asn1.create(
      asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [
      asn1.create(asn1.Class.UNIVERSAL, asn1.Type.OID, false,
        asn1.oidToDer(oids['pkcs5PBES2']).getBytes()),
      asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [
        // keyDerivationFunc
        asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [
          asn1.create(asn1.Class.UNIVERSAL, asn1.Type.OID, false,
            asn1.oidToDer(oids['pkcs5PBKDF2']).getBytes()),
          // PBKDF2-params
          asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [
            // salt
            asn1.create(
              asn1.Class.UNIVERSAL, asn1.Type.OCTETSTRING, false, salt),
            // iteration count
            asn1.create(asn1.Class.UNIVERSAL, asn1.Type.INTEGER, false,
              countBytes.getBytes())
          ])
        ]),
        // encryptionScheme
        asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [
          asn1.create(asn1.Class.UNIVERSAL, asn1.Type.OID, false,
            asn1.oidToDer(encOid).getBytes()),
          // iv
          asn1.create(
            asn1.Class.UNIVERSAL, asn1.Type.OCTETSTRING, false, iv)
        ])
      ])
    ]);
  }
  else if(options.algorithm === '3des') {
    // Do PKCS12 PBE
    dkLen = 24;

    var saltBytes = new forge.util.ByteBuffer(salt);
    var dk = forge.pkcs12.generateKey(password, saltBytes, 1, count, dkLen);
    var iv = forge.pkcs12.generateKey(password, saltBytes, 2, count, dkLen);
    var cipher = forge.des.createEncryptionCipher(dk);
    cipher.start(iv);
    cipher.update(asn1.toDer(obj));
    cipher.finish();
    encryptedData = cipher.output.getBytes();

    encryptionAlgorithm = asn1.create(
      asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [
      asn1.create(asn1.Class.UNIVERSAL, asn1.Type.OID, false,
        asn1.oidToDer(oids['pbeWithSHAAnd3-KeyTripleDES-CBC']).getBytes()),
      // pkcs-12PbeParams
      asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [
        // salt
        asn1.create(asn1.Class.UNIVERSAL, asn1.Type.OCTETSTRING, false, salt),
        // iteration count
        asn1.create(asn1.Class.UNIVERSAL, asn1.Type.INTEGER, false,
          countBytes.getBytes())
      ])
    ]);
  }
  else {
    throw {
      message: 'Cannot encrypt private key. Unknown encryption algorithm.',
      algorithm: options.algorithm
    };
  }

  // EncryptedPrivateKeyInfo
  var rval = asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [
    // encryptionAlgorithm
    encryptionAlgorithm,
    // encryptedData
    asn1.create(
      asn1.Class.UNIVERSAL, asn1.Type.OCTETSTRING, false, encryptedData)
  ]);
  return rval;
};

/**
 * Get new Forge cipher object instance according to PBES2 params block.
 *
 * The returned cipher instance is already started using the IV
 * from PBES2 parameter block.
 *
 * @param oid The PKCS#12 PBE OID (in string notation).
 * @param params The ASN.1 PBES2-params object.
 * @param password The password to decrypt with.
 * @return New cipher object instance.
 */
pki.pbe.getCipherForPBES2 = function(oid, params, password) {
  // get PBE params
  var capture = {};
  var errors = [];
  if(!asn1.validate(params, PBES2AlgorithmsValidator, capture, errors)) {
    throw {
      message: 'Cannot read password-based-encryption algorithm ' +
        'parameters. ASN.1 object is not a supported ' +
        'EncryptedPrivateKeyInfo.',
      errors: errors
    };
  }

  // check oids
  oid = asn1.derToOid(capture.kdfOid);
  if(oid !== pki.oids['pkcs5PBKDF2']) {
    throw {
      message: 'Cannot read encrypted private key. ' +
        'Unsupported key derivation function OID.',
      oid: oid,
      supportedOids: ['pkcs5PBKDF2']
    };
  }
  oid = asn1.derToOid(capture.encOid);
  if(oid !== pki.oids['aes128-CBC'] &&
    oid !== pki.oids['aes192-CBC'] &&
    oid !== pki.oids['aes256-CBC']) {
    throw {
      message: 'Cannot read encrypted private key. ' +
        'Unsupported encryption scheme OID.',
      oid: oid,
      supportedOids: ['aes128-CBC', 'aes192-CBC', 'aes256-CBC']
    };
  }

  // set PBE params
  var salt = capture.kdfSalt;
  var count = forge.util.createBuffer(capture.kdfIterationCount);
  count = count.getInt(count.length() << 3);
  var dkLen;
  if(oid === pki.oids['aes128-CBC']) {
    dkLen = 16;
  }
  else if(oid === pki.oids['aes192-CBC']) {
    dkLen = 24;
  }
  else if(oid === pki.oids['aes256-CBC']) {
    dkLen = 32;
  }

  // decrypt private key using pbe SHA-1 and AES
  var dk = forge.pkcs5.pbkdf2(password, salt, count, dkLen);
  var iv = capture.encIv;
  var cipher = forge.aes.createDecryptionCipher(dk);
  cipher.start(iv);

  return cipher;
};

/**
 * Get new Forge cipher object instance for PKCS#12 PBE.
 *
 * The returned cipher instance is already started using the key & IV
 * derived from the provided password and PKCS#12 PBE salt.
 *
 * @param oid The PKCS#12 PBE OID (in string notation).
 * @param params The ASN.1 PKCS#12 PBE-params object.
 * @param password The password to decrypt with.
 * @return New cipher object instance.
 */
pki.pbe.getCipherForPKCS12PBE = function(oid, params, password) {
  // get PBE params
  var capture = {};
  var errors = [];
  if(!asn1.validate(params, pkcs12PbeParamsValidator, capture, errors)) {
    throw {
      message: 'Cannot read password-based-encryption algorithm ' +
        'parameters. ASN.1 object is not a supported ' +
        'EncryptedPrivateKeyInfo.',
      errors: errors
    };
  }

  var salt = forge.util.createBuffer(capture.salt);
  var count = forge.util.createBuffer(capture.iterations);
  count = count.getInt(count.length() << 3);

  var dkLen, dIvLen, cipherFn;
  switch(oid) {
    case pki.oids['pbeWithSHAAnd3-KeyTripleDES-CBC']:
      dkLen = 24;
      dIvLen = 8;
      cipherFn = forge.des.startDecrypting;
      break;

    case pki.oids['pbewithSHAAnd40BitRC2-CBC']:
      dkLen = 5;
      dIvLen = 8;
      cipherFn = function(key, iv) {
        var cipher = forge.rc2.createDecryptionCipher(key, 40);
        cipher.start(iv, null);
        return cipher;
      };
      break;

    default:
      throw {
        message: 'Cannot read PKCS #12 PBE data block. Unsupported OID.',
        oid: oid
      };
  }

  var key = forge.pkcs12.generateKey(password, salt, 1, count, dkLen);
  var iv = forge.pkcs12.generateKey(password, salt, 2, count, dIvLen);

  return cipherFn(key, iv);
};

pki.pbe.getCipher = function(oid, params, password) {
  switch(oid) {
  case pki.oids['pkcs5PBES2']:
    return pki.pbe.getCipherForPBES2(oid, params, password);
    break;

  case pki.oids['pbeWithSHAAnd3-KeyTripleDES-CBC']:
  case pki.oids['pbewithSHAAnd40BitRC2-CBC']:
    return pki.pbe.getCipherForPKCS12PBE(oid, params, password);
    break;

  default:
    throw {
      message: 'Cannot read encrypted PBE data block. Unsupported OID.',
      oid: oid,
      supportedOids: [
        'pkcs5PBES2',
        'pbeWithSHAAnd3-KeyTripleDES-CBC',
        'pbewithSHAAnd40BitRC2-CBC'
      ]
    };
  }
};

/**
 * Decrypts a ASN.1 PrivateKeyInfo object.
 *
 * @param obj the ASN.1 EncryptedPrivateKeyInfo object.
 * @param password the password to decrypt with.
 *
 * @return the ASN.1 PrivateKeyInfo on success, null on failure.
 */
pki.decryptPrivateKeyInfo = function(obj, password) {
  var rval = null;

  // get PBE params
  var capture = {};
  var errors = [];
  if(!asn1.validate(obj, encryptedPrivateKeyValidator, capture, errors)) {
    throw {
      message: 'Cannot read encrypted private key. ' +
        'ASN.1 object is not a supported EncryptedPrivateKeyInfo.',
      errors: errors
    };
  }

  // get cipher
  var oid = asn1.derToOid(capture.encryptionOid);
  var cipher = pki.pbe.getCipher(oid, capture.encryptionParams, password);

  // get encrypted data
  var encrypted = forge.util.createBuffer(capture.encryptedData);

  cipher.update(encrypted);
  if(cipher.finish()) {
    rval = asn1.fromDer(cipher.output);
  }

  return rval;
};

/**
 * Converts a EncryptedPrivateKeyInfo to PEM format.
 *
 * @param epki the EncryptedPrivateKeyInfo.
 * @param maxline the maximum characters per line, defaults to 64.
 *
 * @return the PEM-formatted encrypted private key.
 */
pki.encryptedPrivateKeyToPem = function(epki, maxline) {
  // convert to DER, then PEM-encode
  var msg = {
    type: 'ENCRYPTED PRIVATE KEY',
    body: asn1.toDer(epki).getBytes()
  };
  return forge.pem.encode(msg, {maxline: maxline});
};

/**
 * Converts a PEM-encoded EncryptedPrivateKeyInfo to ASN.1 format. Decryption
 * is not performed.
 *
 * @param pem the EncryptedPrivateKeyInfo in PEM-format.
 *
 * @return the ASN.1 EncryptedPrivateKeyInfo.
 */
pki.encryptedPrivateKeyFromPem = function(pem) {
  var msg = forge.pem.decode(pem)[0];

  if(msg.type !== 'ENCRYPTED PRIVATE KEY') {
    throw {
      message: 'Could not convert encrypted private key from PEM; PEM header ' +
        'type is "ENCRYPTED PRIVATE KEY".',
      headerType: msg.type
    };
  }
  if(msg.procType && msg.procType.type === 'ENCRYPTED') {
    throw {
      message: 'Could not convert encrypted private key from PEM; ' +
        'PEM is encrypted.'
    };
  }

  // convert DER to ASN.1 object
  return asn1.fromDer(msg.body);
};

/**
 * Encrypts an RSA private key. By default, the key will be wrapped in
 * a PrivateKeyInfo and encrypted to produce a PKCS#8 EncryptedPrivateKeyInfo.
 * This is the standard, preferred way to encrypt a private key.
 *
 * To produce a non-standard PEM-encrypted private key that uses encapsulated
 * headers to indicate the encryption algorithm (old-style non-PKCS#8 OpenSSL
 * private key encryption), set the 'legacy' option to true. Note: Using this
 * option will cause the iteration count to be forced to 1.
 *
 * @param rsaKey the RSA key to encrypt.
 * @param password the password to use.
 * @param options:
 *          algorithm: the encryption algorithm to use
 *            ('aes128', 'aes192', 'aes256', '3des').
 *          count: the iteration count to use.
 *          saltSize: the salt size to use.
 *          legacy: output an old non-PKCS#8 PEM-encrypted+encapsulated
 *            headers (DEK-Info) private key.
 *
 * @return the PEM-encoded ASN.1 EncryptedPrivateKeyInfo.
 */
pki.encryptRsaPrivateKey = function(rsaKey, password, options) {
  // standard PKCS#8
  options = options || {};
  if(!options.legacy) {
    // encrypt PrivateKeyInfo
    var rval = pki.wrapRsaPrivateKey(pki.privateKeyToAsn1(rsaKey));
    rval = pki.encryptPrivateKeyInfo(rval, password, options);
    return pki.encryptedPrivateKeyToPem(rval);
  }

  // legacy non-PKCS#8
  var algorithm;
  var iv;
  var dkLen;
  var cipherFn;
  switch(options.algorithm) {
  case 'aes128':
    algorithm = 'AES-128-CBC';
    dkLen = 16;
    iv = forge.random.getBytes(16);
    cipherFn = forge.aes.createEncryptionCipher;
    break;
  case 'aes192':
    algorithm = 'AES-192-CBC';
    dkLen = 24;
    iv = forge.random.getBytes(16);
    cipherFn = forge.aes.createEncryptionCipher;
    break;
  case 'aes256':
    algorithm = 'AES-256-CBC';
    dkLen = 32;
    iv = forge.random.getBytes(16);
    cipherFn = forge.aes.createEncryptionCipher;
    break;
  case '3des':
    algorithm = 'DES-EDE3-CBC';
    dkLen = 24;
    iv = forge.random.getBytes(8);
    cipherFn = forge.des.createEncryptionCipher;
    break;
  default:
    throw {
      message: 'Could not encrypt RSA private key; unsupported encryption ' +
        'algorithm "' + options.algorithm + '".',
      algorithm: options.algorithm
    };
  }

  // encrypt private key using OpenSSL legacy key derivation
  var dk = evpBytesToKey(password, iv.substr(0, 8), dkLen);
  var cipher = cipherFn(dk);
  cipher.start(iv);
  cipher.update(asn1.toDer(pki.privateKeyToAsn1(rsaKey)));
  cipher.finish();

  var msg = {
    type: 'RSA PRIVATE KEY',
    procType: {
      version: '4',
      type: 'ENCRYPTED'
    },
    dekInfo: {
      algorithm: algorithm,
      parameters: forge.util.bytesToHex(iv).toUpperCase()
    },
    body: cipher.output.getBytes()
  };
  return forge.pem.encode(msg);
};

/**
 * Decrypts an RSA private key.
 *
 * @param pem the PEM-formatted EncryptedPrivateKeyInfo to decrypt.
 * @param password the password to use.
 *
 * @return the RSA key on success, null on failure.
 */
pki.decryptRsaPrivateKey = function(pem, password) {
  var rval = null;

  var msg = forge.pem.decode(pem)[0];

  if(msg.type !== 'ENCRYPTED PRIVATE KEY' &&
    msg.type !== 'PRIVATE KEY' &&
    msg.type !== 'RSA PRIVATE KEY') {
    throw {
      message: 'Could not convert private key from PEM; PEM header type is ' +
        'not "ENCRYPTED PRIVATE KEY", "PRIVATE KEY", or "RSA PRIVATE KEY".',
      headerType: msg.type
    };
  }

  if(msg.procType && msg.procType.type === 'ENCRYPTED') {
    var dkLen;
    var cipherFn;
    switch(msg.dekInfo.algorithm) {
    case 'DES-EDE3-CBC':
      dkLen = 24;
      cipherFn = forge.des.createDecryptionCipher;
      break;
    case 'AES-128-CBC':
      dkLen = 16;
      cipherFn = forge.aes.createDecryptionCipher;
      break;
    case 'AES-192-CBC':
      dkLen = 24;
      cipherFn = forge.aes.createDecryptionCipher;
      break;
    case 'AES-256-CBC':
      dkLen = 32;
      cipherFn = forge.aes.createDecryptionCipher;
      break;
    case 'RC2-40-CBC':
      dkLen = 5;
      cipherFn = function(key) {
        return forge.rc2.createDecryptionCipher(key, 40);
      };
      break;
    case 'RC2-64-CBC':
      dkLen = 8;
      cipherFn = function(key) {
        return forge.rc2.createDecryptionCipher(key, 64);
      };
      break;
    case 'RC2-128-CBC':
      dkLen = 16;
      cipherFn = function(key) {
        return forge.rc2.createDecryptionCipher(key, 128);
      };
      break;
    default:
      throw {
        message: 'Could not decrypt private key; unsupported encryption ' +
          'algorithm "' + msg.dekInfo.algorithm + '".',
        algorithm: msg.dekInfo.algorithm
      };
    }

    // use OpenSSL legacy key derivation
    var iv = forge.util.hexToBytes(msg.dekInfo.parameters);
    var dk = evpBytesToKey(password, iv.substr(0, 8), dkLen);
    var cipher = cipherFn(dk);
    cipher.start(iv);
    cipher.update(forge.util.createBuffer(msg.body));
    if(cipher.finish()) {
      rval = cipher.output.getBytes();
    }
    else {
      return rval;
    }
  }
  else {
    rval = msg.body;
  }

  if(msg.type === 'ENCRYPTED PRIVATE KEY') {
    rval = pki.decryptPrivateKeyInfo(asn1.fromDer(rval), password);
  }
  else {
    // decryption already performed above
    rval = asn1.fromDer(rval);
  }

  if(rval !== null) {
    rval = pki.privateKeyFromAsn1(rval);
  }

  return rval;
};

/**
 * OpenSSL's legacy key derivation function.
 *
 * See: http://www.openssl.org/docs/crypto/EVP_BytesToKey.html
 *
 * @param password the password to derive the key from.
 * @param salt the salt to use.
 * @param dkLen the number of bytes needed for the derived key.
 */
function evpBytesToKey(password, salt, dkLen) {
  var digests = [md5(password + salt)];
  for(var length = 16, i = 1; length < dkLen; ++i, length += 16) {
    digests.push(md5(digests[i - 1] + password + salt));
  }
  return digests.join('').substr(0, dkLen);
}

function md5(bytes) {
  return forge.md.md5.create().update(bytes).digest().getBytes();
}

/**
 * Sets an RSA public key from BigIntegers modulus and exponent.
 *
 * @param n the modulus.
 * @param e the exponent.
 *
 * @return the public key.
 */
pki.setRsaPublicKey = pki.rsa.setPublicKey;

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
pki.setRsaPrivateKey = pki.rsa.setPrivateKey;

} // end module implementation

/* ########## Begin module wrapper ########## */
var name = 'pki';
var deps = [
  './aes',
  './asn1',
  './des',
  './jsbn',
  './md',
  './mgf',
  './oids',
  './pem',
  './pbkdf2',
  './pkcs12',
  './pss',
  './random',
  './rc2',
  './rsa',
  './util'
];
var nodeDefine = null;
if(typeof define !== 'function') {
  // NodeJS -> AMD
  if(typeof module === 'object' && module.exports) {
    nodeDefine = function(ids, factory) {
      factory(require, module);
    };
  }
  // <script>
  else {
    if(typeof forge === 'undefined') {
      forge = {};
    }
    initModule(forge);
  }
}
// AMD
var defineDeps = ['require', 'module'].concat(deps);
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
if(nodeDefine) {
  nodeDefine(defineDeps, defineFunc);
}
else if(typeof define === 'function') {
  define([
    "require",
    "module",
    "./aes",
    "./asn1",
    "./des",
    "./jsbn",
    "./md",
    "./mgf",
    "./oids",
    "./pem",
    "./pbkdf2",
    "./pkcs12",
    "./pss",
    "./random",
    "./rc2",
    "./rsa",
    "./util"
  ] , function() {
    defineFunc.apply(null, Array.prototype.slice.call(arguments, 0));
  });
}
})();
