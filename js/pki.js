/**
 * Javascript implementation of a basic Public Key Infrastructure, including
 * support for RSA public and private keys.
 *
 * @author Dave Longley
 *
 * Copyright (c) 2010-2013 Digital Bazaar, Inc.
 */
(function() {
/* ########## Begin module implementation ########## */
function initModule(forge) {

// shortcut for asn.1 API
var asn1 = forge.asn1;

/* Public Key Infrastructure (PKI) implementation. */
var pki = forge.pki = forge.pki || {};

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
 * Converts an RSA private key from PEM format.
 *
 * @param pem the PEM-formatted private key.
 * @param password the password for encrypted parivate key.
 *
 * @return the private key.
 */
pki.privateKeyFromPem = function(pem, password) {
  var msg = forge.pem.decode(pem)[0];

  if(msg.type !== 'PRIVATE KEY' && msg.type !== 'RSA PRIVATE KEY') {
    throw {
      message: 'Could not convert private key from PEM; PEM header type is ' +
        'not "PRIVATE KEY" or "RSA PRIVATE KEY".',
      headerType: msg.type
    };
  }
  if(msg.procType && msg.procType.type === 'ENCRYPTED') {
    if(typeof password === 'undefined') {
      throw {
        message: 'Could not convert a encrypted private key without password.'
      };
    }
    var algSettings = setAlgorithmSettings(msg.dekInfo.algorithm);
    var iv = setIV(msg.dekInfo.parameters, algSettings);
    
    var key = getSecretKey(password, iv, algSettings);
    var cipher = algSettings.cipherFn(key, iv);
    var encrypted = forge.util.createBuffer(msg.body);
    cipher.update(encrypted);
    if(cipher.finish()) {
      msg.body = cipher.output;
    }
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

function setAlgorithmSettings(alg) {
  switch(alg) {
    case 'DES-EDE3-CBC':
      return {
        cipherFn: forge.des.startDecrypting,
        keyLength: 24,
        ivLength: 8
      };
    case 'AES-128-CBC':
      return {
        cipherFn: forge.aes.startDecrypting,
        keyLength: 16,
        ivLength: 16
      };
    case 'AES-192-CBC':
      return {
        cipherFn: forge.aes.startDecrypting,
        keyLength: 24,
        ivLength: 16
      };
    case 'AES-256-CBC':
      return {
        cipherFn: forge.aes.startDecrypting,
        keyLength: 32,
        ivLength: 16
      };
    case 'DES-CBC':
      return {
        cipherFn: forge.des.startDecrypting,
        keyLength: 8,
        ivLength: 8
      };
    default:
      throw {
        message: 'Unsupported encryption.',
        alg: alg
      };
  }
}

function setIV(s, algSettings) {
  var len = s.length / 2;
  if (len != algSettings.ivLength) {
    throw {
        message: 'Expected IV length.',
        length: len,
        ivLength: algSettings.ivLength,
    };
  }
  var iv = forge.util.createBuffer();
  for (var j=0; j<len; j++) {
      iv.putInt(parseInt(s.substring(j*2, j*2 + 2), 16));
  }
  return iv;
}

function getSecretKey(pwd, iv, algSettings) {
  if(pwd.constructor != String) {
    pwd = pwd.data;
  }
  if(iv.constructor != String) {
    iv = iv.data;
  }

  var key = forge.util.createBuffer();
  var offset = 0;
  var bytesNeeded = algSettings.keyLength;

  var md5 = forge.md.md5.create();
  for (;;) {
      md5.update(pwd);
      md5.update(iv);
      
      var b = md5.digest();
      var len = (bytesNeeded > b.length()) ? b.length() : bytesNeeded;
      
      key.putBytes(b.data);
      offset += len;
      
      // check if we need any more
      bytesNeeded = algSettings.keyLength - offset;
      if (bytesNeeded === 0) {
          break;
      }

      // do another round
      md5 = forge.md.md5.create();
      md5.update(b.data);
  }
  
  return key;
}

} // end module implementation

/* ########## Begin module wrapper ########## */
var name = 'pki';
if(typeof define !== 'function') {
  // NodeJS -> AMD
  if(typeof module === 'object' && module.exports) {
    var nodeJS = true;
    define = function(ids, factory) {
      factory(require, module);
    };
  }
  // <script>
  else {
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
  './oids',
  './pbe',
  './pem',
  './pbkdf2',
  './pkcs12',
  './pss',
  './rsa',
  './util',
  './x509'
], function() {
  defineFunc.apply(null, Array.prototype.slice.call(arguments, 0));
});
})();
