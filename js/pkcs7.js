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
      des: require('./des'),
      pki: require('./pki'),
      random: require('./random'),
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
 * Converts a PKCS#7 message to PEM format.
 *
 * @param msg The PKCS#7 message object
 * @param maxline The maximum characters per line, defaults to 64.
 *
 * @return The PEM-formatted PKCS#7 message.
 */
p7.messageToPem = function(msg, maxline) {
   var out = asn1.toDer(msg.toAsn1());
   out = forge.util.encode64(out.getBytes(), maxline || 64);
   return (
      '-----BEGIN PKCS7-----\r\n' +
      out +
      '\r\n-----END PKCS7-----');
}

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
      case forge.pki.oids.envelopedData:
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
      encContent: {
         algorithm: asn1.derToOid(capture.encAlgorithm),
         parameter: capture.encParameter,
         content: capture.encKey
      }
   };
};

/**
 * Converts a single recipientInfo object to an ASN.1 object.
 *
 * @param obj The recipientInfo object.
 *
 * @return The ASN.1 representation of a RecipientInfo.
 */
var _recipientInfoToAsn1 = function(obj) {
   return asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [
      // Version
      asn1.create(asn1.Class.UNIVERSAL, asn1.Type.INTEGER, false,
         String.fromCharCode(obj.version)),
      // IssuerAndSerialNumber
      asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [
         // Name
         forge.pki.distinguishedNameToAsn1({ attributes: obj.issuer }),
         // Serial
         asn1.create(asn1.Class.UNIVERSAL, asn1.Type.INTEGER, false,
            forge.util.hexToBytes(obj.serialNumber)),
      ]),
      // KeyEncryptionAlgorithmIdentifier
      asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [
         // Algorithm
         asn1.create(asn1.Class.UNIVERSAL, asn1.Type.OID, false,
            asn1.oidToDer(obj.encContent.algorithm).getBytes()),
         // Parameter, force NULL, only RSA supported for now.
         asn1.create(asn1.Class.UNIVERSAL, asn1.Type.NULL, false, '')
      ]),
      // EncryptedKey
      asn1.create(asn1.Class.UNIVERSAL, asn1.Type.OCTETSTRING, false,
         obj.encContent.content)
   ]);
}

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
 * Map an array of recipientInfo objects to ASN.1 objects.
 *
 * @param recipientsArr Array of recipientInfo objects.
 *
 * @return Array of ASN.1 representations RecipientInfo.
 */
var _recipientInfosToAsn1 = function(recipientsArr) {
   var ret = [];
   for(var i = 0; i < recipientsArr.length; i ++) {
      ret.push(_recipientInfoToAsn1(recipientsArr[i]));
   }
   return ret;
};

/**
 * Map messages encrypted content to ASN.1 objects.
 *
 * @param ec The encContent object of the message.
 *
 * @return ASN.1 representation of the encContent object (SEQUENCE).
 */
var _encContentToAsn1 = function(ec) {
   return [
      // ContentType, always Data for the moment
      asn1.create(asn1.Class.UNIVERSAL, asn1.Type.OID, false,
         asn1.oidToDer(forge.pki.oids.data).getBytes()),
      // ContentEncryptionAlgorithmIdentifier
      asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [
         // Algorithm
         asn1.create(asn1.Class.UNIVERSAL, asn1.Type.OID, false,
            asn1.oidToDer(ec.algorithm).getBytes()),
         // Parameters (IV)
         asn1.create(asn1.Class.UNIVERSAL, asn1.Type.OCTETSTRING, false,
            ec.parameter.getBytes())
      ]),
      // [0] EncryptedContent
      asn1.create(asn1.Class.CONTEXT_SPECIFIC, 0, true, [
         asn1.create(asn1.Class.UNIVERSAL, asn1.Type.OCTETSTRING, false,
            ec.content.getBytes())
      ]),
   ];
}

/**
 * Creates an empty PKCS#7 message of type EnvelopedData.
 *
 * @return the message.
 */
p7.createEnvelopedData = function() {
   var msg = {
      type: forge.pki.oids.envelopedData,
      version: 0,
      recipients: [],
      encContent: {
         algorithm: forge.pki.oids['aes256-CBC']
      },

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
         if(contentType !== forge.pki.oids.data) {
            throw {
               message: 'Unsupported PKCS#7 message. ' +
                  'Only contentType Data supported within EnvelopedData.'
            };
         }

         var content = "";
         if(capture.encContent.constructor === Array) {
            for(var i = 0; i < capture.encContent.length; i ++) {
               if(capture.encContent[i].type !== asn1.Type.OCTETSTRING) {
                  throw {
                     message: 'Malformed PKCS#7 message, expecting encrypted '
                        + 'content constructed of only OCTET STRING objects.'
                  };
               }
               content += capture.encContent[i].value;
            }
         } else {
            content = capture.encContent;
         }

         msg.version = capture.version.charCodeAt(0);
         msg.recipients = _recipientInfosFromAsn1(capture.recipientInfos.value);
         msg.encContent = {
            algorithm: asn1.derToOid(capture.encAlgorithm),
            parameter: forge.util.createBuffer(capture.encParameter),
            content: forge.util.createBuffer(content)
         };
      },

      toAsn1: function() {
         // ContentInfo
         return asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [
            // ContentType
            asn1.create(asn1.Class.UNIVERSAL, asn1.Type.OID, false,
               asn1.oidToDer(msg.type).getBytes()),
            // [0] EnvelopedData
            asn1.create(asn1.Class.CONTEXT_SPECIFIC, 0, true, [
               asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [
                  // Version
                  asn1.create(asn1.Class.UNIVERSAL, asn1.Type.INTEGER, false,
                     String.fromCharCode(msg.version)),
                  // RecipientInfos
                  asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SET, true,
                     _recipientInfosToAsn1(msg.recipients)),
                  // EncryptedContentInfo
                  asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true,
                     _encContentToAsn1(msg.encContent))
               ])
            ])
         ]);
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
               if(rAttr[j].type !== sAttr[j].type
                  || rAttr[j].value !== sAttr[j].value) {
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
            switch(recipient.encContent.algorithm) {
               case forge.pki.oids.rsaEncryption:
                  var key = privKey.decrypt(recipient.encContent.content);
                  msg.encContent.key = forge.util.createBuffer(key);
                  break;

               default:
                  throw {
                     message: 'Unsupported asymmetric cipher, '
                        + 'OID ' + recipient.encContent.algorithm
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
               case forge.pki.oids['aes128-CBC']:
               case forge.pki.oids['aes192-CBC']:
               case forge.pki.oids['aes256-CBC']:
                  ciph = forge.aes.createDecryptionCipher(msg.encContent.key);
                  break;

               case forge.pki.oids['des-EDE3-CBC']:
                  ciph = forge.des.createDecryptionCipher(msg.encContent.key);
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

            msg.content = ciph.output;
         }
      },

      /**
       * Add (another) entity to list of recipients.
       *
       * @param cert The certificate of the entity to add.
       */
      addRecipient: function(cert) {
         msg.recipients.push({
            version: 0,
            issuer: cert.subject.attributes,
            serialNumber: cert.serialNumber,
            encContent: {
               // We simply assume rsaEncryption here, since forge.pki only
               // supports RSA so far.  If the PKI module supports other
               // ciphers one day, we need to modify this one as well.
               algorithm: forge.pki.oids.rsaEncryption,
               key: cert.publicKey
            }
         });
      },

      /**
       * Encrypt enveloped content.
       *
       * This function supports two optional arguments, cipher and key, which
       * can be used to influence symmetric encryption.  Unless cipher is
       * provided, the cipher specified in encContent.algorithm is used
       * (defaults to AES-256-CBC).  If no key is provided, encContent.key
       * is (re-)used.  If that one's not set, a random key will be generated
       * automatically.
       *
       * @param [key] The key to be used for symmetric encryption.
       * @param [cipher] The OID of the symmetric cipher to use.
       */
      encrypt: function(key, cipher) {
         // Part 1: Symmetric encryption
         if(msg.encContent.content === undefined) {
            cipher = cipher || msg.encContent.algorithm;
            key = key || msg.encContent.key;

            var keyLen, ivLen;
            switch(cipher) {
               case forge.pki.oids['aes128-CBC']:
                  keyLen = 16;
                  ivLen = 16;
                  ciphFn = forge.aes.createEncryptionCipher;
                  break;

               case forge.pki.oids['aes192-CBC']:
                  keyLen = 24;
                  ivLen = 16;
                  ciphFn = forge.aes.createEncryptionCipher;
                  break;

               case forge.pki.oids['aes256-CBC']:
                  keyLen = 32;
                  ivLen = 16;
                  ciphFn = forge.aes.createEncryptionCipher;
                  break;

               case forge.pki.oids['des-EDE3-CBC']:
                  keyLen = 24;
                  ivLen = 8;
                  ciphFn = forge.des.createEncryptionCipher;
                  break;

               default:
                  throw {
                     message: 'Unsupported symmetric cipher, OID ' + cipher
                  };
            }

            if(key === undefined) {
               key = forge.util.createBuffer(forge.random.getBytes(keyLen));
            } else if(key.length() != keyLen) {
               throw {
                  message: 'Symmetric key has wrong length, '
                     + 'got ' + key.length() + ' bytes, expected ' + keyLen
               };
            }

            // Keep a copy of the key & IV in the object, so the caller can
            // use it for whatever reason.
            msg.encContent.key = key;
            msg.encContent.parameter
               = forge.util.createBuffer(forge.random.getBytes(ivLen));

            ciph = ciphFn(key);
            ciph.start(msg.encContent.parameter.copy());
            ciph.update(msg.content);

            // The finish function does PKCS#7 padding by default, therefore
            // no action required by us.
            if(!ciph.finish()) {
               throw {
                  message: 'Symmetric encryption failed.'
               };
            }

            msg.encContent.content = ciph.output;
         }

         // Part 2: asymmetric encryption for each recipient
         for(var i = 0; i < msg.recipients.length; i ++) {
            var recipient = msg.recipients[i];

            if(recipient.encContent.content !== undefined) {
               continue;   // Nothing to do, encryption already done.
            }

            switch(recipient.encContent.algorithm) {
               case forge.pki.oids.rsaEncryption:
                  recipient.encContent.content =
                     recipient.encContent.key.encrypt(msg.encContent.key.data);
                  break;

               default:
                  throw {
                     message: 'Unsupported asymmetric cipher, OID '
                        + recipient.encContent.algorithm
                  };
            }
         }
      }
   };
   return msg;
};

})();
