/**
 * Javascript implementation of PKCS#7 v1.5.  Currently only certain parts of
 * PKCS#7 are implemented, especially the enveloped-data content type.
 *
 * @author Stefan Siegl
 *
 * Copyright (c) 2012 Stefan Siegl <stesie@brokenpipe.de>
 *
 * The ASN.1 representation of PKCS#7 is as follows
 * (see RFC #2315 for details):
 *
 * A PKCS#7 message consists of a ContentInfo on root level, which may
 * contain any number of further ContentInfo nested into it.
 *
 * ContentInfo ::= SEQUENCE {
 *    contentType                ContentType,
 *    content               [0]  EXPLICIT ANY DEFINED BY contentType OPTIONAL
 * }
 *
 * ContentType ::= OBJECT IDENTIFIER
 *
 * Currently this implementation only supports ContentType = EnvelopedData
 * on root level.  The EnvelopedData element may contain only a ContentInfo
 * of ContentType Data, i.e. plain data.  Further nesting is not (yet)
 * supported.
 *
 * EnvelopedData ::= SEQUENCE {
 *    version                    Version,
 *    recipientInfos             RecipientInfos,
 *    encryptedContentInfo       EncryptedContentInfo
 * }
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
(function() {

// define forge
var forge;
if(typeof(window) !== 'undefined') {
   forge = window.forge = window.forge || {};
}
// define node.js module
else if(typeof(module) !== 'undefined' && module.exports) {
   forge = {
      aes: require('./aes'),
      asn1: require('./asn1'),
      oids: require('./oids'),
      pki: require('./pki'),
      util: require('./util')
   };
   module.exports = forge.pkcs7 = {};
}

// shortcut for ASN.1 API
var asn1 = forge.asn1;

// shortcut for PKCS#7 API
var p7 = forge.pkcs7;

var contentInfoValidator = {
   name: 'ContentInfo',
   tagClass: asn1.Class.UNIVERSAL,
   type: asn1.Type.SEQUENCE,
   constructed: true,
   value: [{
      name: 'ContentInfo.ContentType',
      tagClass: asn1.Class.UNIVERSAL,
      type: asn1.Type.OID,
      constructed: false,
      capture: 'contentType'
   }, {
      name: 'ContentInfo.content',
      tagClass: asn1.Class.CONTEXT_SPECIFIC,
      type: 0,
      constructed: true,
      optional: true,
      captureAsn1: 'content'
   }]
};

var envelopedDataValidator = {
   name: 'EnvelopedData',
   tagClass: asn1.Class.UNIVERSAL,
   type: asn1.Type.SEQUENCE,
   constructed: true,
   value: [{
      name: 'EnvelopedData.Version',
      tagClass: asn1.Class.UNIVERSAL,
      type: asn1.Type.INTEGER,
      constructed: false,
      capture: 'version'
   }, {
      name: 'EnvelopedData.RecipientInfos',
      tagClass: asn1.Class.UNIVERSAL,
      type: asn1.Type.SET,
      constructed: true,
      captureAsn1: 'recipientInfos'
   }, {
      name: 'EnvelopedData.EncryptedContentInfo',
      tagClass: asn1.Class.UNIVERSAL,
      type: asn1.Type.SEQUENCE,
      constructed: true,
      value: [{
         name: 'EnvelopedData.EncryptedContentInfo.contentType',
         tagClass: asn1.Class.UNIVERSAL,
         type: asn1.Type.OID,
         constructed: false,
         capture: 'contentType'
      }, {
         name: 'EnvelopedData.EncryptedContentInfo.contentEncryptionAlgorithm',
         tagClass: asn1.Class.UNIVERSAL,
         type: asn1.Type.SEQUENCE,
         constructed: true,
         value: [{
            name: 'contentEncryptionAlgorithm.algorithm',
            tagClass: asn1.Class.UNIVERSAL,
            type: asn1.Type.OID,
            constructed: false,
            capture: 'encAlgorithm'
         }, {
            name: 'contentEncryptionAlgorithm.parameter',
            tagClass: asn1.Class.UNIVERSAL,
            constructed: false,
            capture: 'encParameter'
         }]
      }, {
         name: 'EnvelopedData.EncryptedContentInfo.encryptedContent',
         tagClass: asn1.Class.CONTEXT_SPECIFIC,
         type: 0,
         constructed: false,
         capture: 'encContent'
      }]
   }]
};

var recipientInfoValidator = {
   name: 'RecipientInfo',
   tagClass: asn1.Class.UNIVERSAL,
   type: asn1.Type.SEQUENCE,
   constructed: true,
   value: [{
      name: 'RecipientInfo.version',
      tagClass: asn1.Class.UNIVERSAL,
      type: asn1.Type.INTEGER,
      constructed: false,
      capture: 'version'
   }, {
      name: 'RecipientInfo.issuerAndSerial',
      tagClass: asn1.Class.UNIVERSAL,
      type: asn1.Type.SEQUENCE,
      constructed: true,
      value: [{
         name: 'RecipientInfo.issuerAndSerial.issuer',
         tagClass: asn1.Class.UNIVERSAL,
         type: asn1.Type.SEQUENCE,
         constructed: true,
         captureAsn1: 'issuer'
      }, {
         name: 'RecipientInfo.issuerAndSerial.serialNumber',
         tagClass: asn1.Class.UNIVERSAL,
         type: asn1.Type.INTEGER,
         constructed: false,
         capture: 'serial'
      }]
   }, {
      name: 'RecipientInfo.keyEncryptionAlgorithm',
      tagClass: asn1.Class.UNIVERSAL,
      type: asn1.Type.SEQUENCE,
      constructed: true,
      value: [{
         name: 'RecipientInfo.keyEncryptionAlgorithm.algorithm',
         tagClass: asn1.Class.UNIVERSAL,
         type: asn1.Type.OID,
         constructed: false,
         capture: 'encAlgorithm'
      }, {
         name: 'RecipientInfo.keyEncryptionAlgorithm.parameter',
         tagClass: asn1.Class.UNIVERSAL,
         constructed: false,
         capture: 'encParameter'
      }]
   }, {
      name: 'RecipientInfo.encryptedKey',
      tagClass: asn1.Class.UNIVERSAL,
      type: asn1.Type.OCTETSTRING,
      constructed: false,
      capture: 'encKey'
   }]
};

      

/**
 * Converts a PKCS#7 message from PEM format.
 *
 * @param pem the PEM-formatted PKCS#7 message.
 *
 * @return the PKCS#7 message.
 */
p7.messageFromPem = function(pem) {
   var der = forge.pki.pemToDer(pem);
   var obj = asn1.fromDer(der);
   return p7.messageFromAsn1(obj);
};

/**
 * Converts a PKCS#7 message from an ASN.1 object.
 *
 * @param obj the ASN.1 representation of a ContentInfo.
 *
 * @return the PKCS#7 message.
 */
p7.messageFromAsn1 = function(obj) {
   // validate root level ContentInfo and capture data
   var capture = {};
   var errors = [];
   if(!asn1.validate(obj, contentInfoValidator, capture, errors))
   {
      throw {
         message: 'Cannot read PKCS#7 message. ' +
            'ASN.1 object is not an PKCS#7 ContentInfo.',
         errors: errors
      };
   }

   var contentType = asn1.derToOid(capture.contentType);
   var msg;

   switch(contentType) {
      case forge.oids.envelopedData:
         msg = p7.createEnvelopedData();
         break;

      default:
         throw {
            message: 'Cannot read PKCS#7 message. ContentType with OID ' +
               contentType + ' is not (yet) supported.'
         };
   }

   msg.fromAsn1(capture.content.value[0]);
   return msg;
};

/**
 * Converts a single RecipientInfo from an ASN.1 object.
 *
 * @param obj The ASN.1 representation of a RecipientInfo.
 *
 * @return The recipientInfo object.
 */
var _recipientInfoFromAsn1 = function(obj) {
   // Validate EnvelopedData content block and capture data.
   var capture = {};
   var errors = [];
   if(!asn1.validate(obj, recipientInfoValidator, capture, errors))
   {
      throw {
         message: 'Cannot read PKCS#7 message. ' +
            'ASN.1 object is not an PKCS#7 EnvelopedData.',
         errors: errors
      };
   }

   return {
      version: capture.version.charCodeAt(0),
      issuer: forge.pki.RDNAttributesAsArray(capture.issuer),
      serialNumber: forge.util.createBuffer(capture.serial).toHex(),
      encKey: {
         algorithm: asn1.derToOid(capture.encAlgorithm),
         parameter: capture.encParameter,
         key: capture.encKey
      }
   };
};

/**
 * Map a set of RecipientInfo ASN.1 objects to recipientInfo objects.
 *
 * @param objArr Array of ASN.1 representations RecipientInfo (i.e. SET OF).
 *
 * @return array of recipientInfo objects.
 */
var _recipientInfosFromAsn1 = function(objArr) {
   var ret = [];
   for(var i = 0; i < objArr.length; i ++) {
      ret.push(_recipientInfoFromAsn1(objArr[i]));
   }
   return ret;
};

/**
 * Creates an empty PKCS#7 message of type EnvelopedData.
 *
 * @return the message.
 */
p7.createEnvelopedData = function() {
   var msg = {
      type: forge.oids.envelopedData,

      /**
       * Reads an EnvelopedData content block (in ASN.1 format)
       *
       * @param obj The ASN.1 representation of the EnvelopedData content block
       */
      fromAsn1: function(obj) {
         // Validate EnvelopedData content block and capture data.
         var capture = {};
         var errors = [];
         if(!asn1.validate(obj, envelopedDataValidator, capture, errors))
         {
            throw {
               message: 'Cannot read PKCS#7 message. ' +
                  'ASN.1 object is not an PKCS#7 EnvelopedData.',
               errors: errors
            };
         }

         // Check contentType, so far we only support (raw) Data.
         var contentType = asn1.derToOid(capture.contentType);
         if(contentType !== forge.oids.data) {
            throw {
               message: 'Unsupported PKCS#7 message. ' +
                  'Only contentType Data supported within EnvelopedData.'
            };
         }

         msg.version = capture.version.charCodeAt(0);
         msg.recipients = _recipientInfosFromAsn1(capture.recipientInfos.value);
         msg.encContent = {
            algorithm: asn1.derToOid(capture.encAlgorithm),
            parameter: forge.util.createBuffer(capture.encParameter),
            content: forge.util.createBuffer(capture.encContent)
         };
      },

      /**
       * Find recipient by X.509 certificate's subject.
       *
       * @param cert The certificate for which's subject to look for.
       *
       * @return The recipient object
       */
      findRecipient: function(cert) {
         var sAttr = cert.subject.attributes;

         for(var i = 0; i < msg.recipients.length; i ++) {
            var r = msg.recipients[i];
            var rAttr = r.issuer;

            if(r.serialNumber !== cert.serialNumber) {
               continue;
            }

            if(rAttr.length !== sAttr.length) {
               continue;
            }

            var match = true;
            for(var j = 0; j < sAttr.length; j ++) {
               if(rAttr[j].type !== sAttr[j].type || rAttr[j].value !== sAttr[j].value) {
                  match = false;
                  break;
               }
            }

            if(match) {
               return r;
            }
         }
      },

      /**
       * Decrypt enveloped content
       *
       * @param recipient The recipient object related to the private key
       * @param privKey The (RSA) private key object
       */
      decrypt: function(recipient, privKey) {
         if(msg.encContent.key === undefined && recipient !== undefined
            && privKey !== undefined) {
            switch(recipient.encKey.algorithm) {
               case forge.oids.rsaEncryption:
                  var key = privKey.decrypt(recipient.encKey.key);
                  msg.encContent.key = forge.util.createBuffer(key);
                  break;

               default:
                  throw {
                     message: 'Unsupported asymmetric cipher, '
                        + 'OID ' + recipient.encKey.algorithm
                  };
            }
         }

         if(msg.encContent.key === undefined) {
            throw {
               message: 'Symmetric key not available.'
            };
         }

         if(msg.content === undefined) {
            var ciph;

            switch(msg.encContent.algorithm) {
               case forge.oids['aes128-CBC']:
               case forge.oids['aes192-CBC']:
               case forge.oids['aes256-CBC']:
                  ciph = forge.aes.createDecryptionCipher(msg.encContent.key);
                  break;

               default:
                  throw {
                     message: 'Unsupported symmetric cipher, '
                        + 'OID ' + recipient.encContent.algorithm,
                  };
            }

            ciph.start(msg.encContent.parameter);
            ciph.update(msg.encContent.content);
            if(!ciph.finish()) {
               throw {
                  message: 'Symmetric decryption failed.'
               };
            }

            msg.content = ciph.output.data;
         }
      }
   };
   return msg;
};

})();
