/**
 * Javascript implementation of PKCS#12.
 *
 * @author Dave Longley
 *
 * Copyright (c) 2010-2012 Digital Bazaar, Inc.
 *
 * The ASN.1 representation of PKCS#7 is as follows
 * (see RFC #2315 for details, http://www.ietf.org/rfc/rfc2315.txt):
 *
 * PFX ::= SEQUENCE {
 *   version  INTEGER {v3(3)}(v3,...),
 *   authSafe ContentInfo,
 *   macData  MacData OPTIONAL
 * }
 *
 * MacData ::= SEQUENCE {
 *   mac DigestInfo,
 *   macSalt OCTET STRING,
 *   iterations INTEGER DEFAULT 1
 * }
 * Note: The iterations default is for historical reasons and its use is
 * deprecated. A higher value, like 1024, is recommended.
 *
 * ContentInfo ::= SEQUENCE {
 *   contentType ContentType,
 *   content     [0] EXPLICIT ANY DEFINED BY contentType OPTIONAL
 * }
 *
 * ContentType ::= OBJECT IDENTIFIER
 *
 * AuthenticatedSafe ::= SEQUENCE OF ContentInfo
 * -- Data if unencrypted
 * -- EncryptedData if password-encrypted
 * -- EnvelopedData if public key-encrypted
 *
 *
 * SafeContents ::= SEQUENCE OF SafeBag
 *
 * SafeBag ::= SEQUENCE {
 *   bagId     BAG-TYPE.&id ({PKCS12BagSet})
 *   bagValue  [0] EXPLICIT BAG-TYPE.&Type({PKCS12BagSet}{@bagId}),
 *   bagAttributes SET OF PKCS12Attribute OPTIONAL
 * }
 *
 * PKCS12Attribute ::= SEQUENCE {
 *   attrId ATTRIBUTE.&id ({PKCS12AttrSet}),
 *   attrValues SET OF ATTRIBUTE.&Type ({PKCS12AttrSet}{@attrId})
 * } -- This type is compatible with the X.500 type ’Attribute’
 *
 * PKCS12AttrSet ATTRIBUTE ::= {
 *   friendlyName | -- from PKCS #9
 *   localKeyId, -- from PKCS #9
 *   ... -- Other attributes are allowed
 * }
 *
 * CertBag ::= SEQUENCE {
 *   certId    BAG-TYPE.&id   ({CertTypes}),
 *   certValue [0] EXPLICIT BAG-TYPE.&Type ({CertTypes}{@certId})
 * }
 *
 * x509Certificate BAG-TYPE ::= {OCTET STRING IDENTIFIED BY {certTypes 1}}
 *   -- DER-encoded X.509 certificate stored in OCTET STRING
 *
 * sdsiCertificate BAG-TYPE ::= {IA5String IDENTIFIED BY {certTypes 2}}
 * -- Base64-encoded SDSI certificate stored in IA5String
 *
 * CertTypes BAG-TYPE ::= {
 *   x509Certificate |
 *   sdsiCertificate,
 *   ... -- For future extensions
 * }
 */
(function() {

// define forge
if(typeof(window) !== 'undefined') {
  var forge = window.forge = window.forge || {};
}
// define node.js module
else if(typeof(module) !== 'undefined' && module.exports) {
  var forge = {
    asn1: require('./asn1'),
    pki: require('./pki'),
    util: require('./util')
  };
  module.exports = forge.pkcs12 = {};
}

// shortcut for asn.1 & PKI API
var asn1 = forge.asn1;
var pki = forge.pki;
var oids = pki.oids;

// shortcut for PKCS#12 API
var p12 = forge.pkcs12 = forge.pkcs12 || {};


/**
 * Wraps a private key and certificate in a PKCS#12 PFX wrapper. If a
 * password is provided then the private key will be encrypted.
 *
 * @param key the private key.
 * @param cert the certificate.
 * @param password the password to use.
 *
 * @return the PKCS#12 PFX ASN.1 object.
 */
p12.toPkcs12Asn1 = function(key, cert, password) {
  // TODO: tests (pkcs12-related code is untested)
  // TODO: implement password-based-encryption for the whole package

  // create safe bag for private key
  var keyBag = null;
  if(key !== null) {
    var pkAsn1 = pki.wrapRsaPrivateKey(pki.privateKeyToAsn1(key));
    if(password === null) {
      // no encryption
      keyBag = asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [
        // bagId
        asn1.create(asn1.Class.UNIVERSAL, asn1.Type.OID, false,
          asn1.oidToDer(oids['keyBag']).getBytes()),
        // bagValue
        asn1.create(asn1.Class.CONTEXT_SPECIFIC, 0, false,
          // PrivateKeyInfo
          asn1.toDer(pkAsn1).getBytes())
        // bagAttributes (OPTIONAL)
      ]);
    }
    else {
      // encrypted PrivateKeyInfo
      keyBag = asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [
        // bagId
        asn1.create(asn1.Class.UNIVERSAL, asn1.Type.OID, false,
          asn1.oidToDer(oids['pkcs8ShroudedKeyBag']).getBytes()),
        // bagValue
        asn1.create(asn1.Class.CONTEXT_SPECIFIC, 0, false,
          // EncryptedPrivateKeyInfo
          asn1.toDer(pki.encryptPrivateKeyInfo(
            pkAsn1, password)).getBytes())
        // bagAttributes (OPTIONAL)
      ]);
    }
  }

  // create safe bag for certificate
  if(cert !== null) {
    var certAsn1 = pki.certificateToAsn1(cert);
    var certSafeBag =
      asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [
        // bagId
        asn1.create(asn1.Class.UNIVERSAL, asn1.Type.OID, false,
          asn1.oidToDer(oids['certBag']).getBytes()),
        // bagValue
        asn1.create(asn1.Class.CONTEXT_SPECIFIC, 0, false,
          // CertBag
          asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [
            // certId
            asn1.create(asn1.Class.UNIVERSAL, asn1.Type.OID, false,
              asn1.oidToDer(oids['x509Certificate']).getBytes()),
            // certValue (x509Certificate)
            asn1.create(
              asn1.Class.UNIVERSAL, asn1.Type.OCTETSTRING, false,
              asn1.toDer(certAsn1).getBytes())
            ]))
        // bagAttributes (OPTIONAL)
      ]);
  }

  // create SafeContents
  var bags = [];
  if(key !== null) {
    bags.push(keyBag);
  }
  if(cert !== null) {
    bags.push(certSafeBag);
  }
  var safeContents =
    asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, bags);

  // create AuthenticatedSafe
  var safe = asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [
    // PKCS#7 ContentInfo
    asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [
      // contentType
      asn1.create(asn1.Class.UNIVERSAL, asn1.Type.OID, false,
        // OID for the content type is 'data'
        asn1.oidToDer(oids['data']).getBytes()),
      // content
      asn1.toDer(safeContents).getBytes()
    ])
  ]);

  // PFX
  return asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [
    // version (3)
    asn1.create(asn1.Class.UNIVERSAL, asn1.Type.INTEGER, false,
      String.fromCharCode(0x03)),
    // PKCS#7 ContentInfo
    asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [
      // contentType
      asn1.create(asn1.Class.UNIVERSAL, asn1.Type.OID, false,
        // OID for the content type is 'data'
        asn1.oidToDer(oids['data']).getBytes()),
      // content
      pki.toDer(safe).getBytes()
    ])
  ]);
};

})();
