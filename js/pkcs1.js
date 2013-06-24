/**
 * Partial implementation of PKCS#1 v2.2: RSA-OEAP
 *
 * Modified but based on the following MIT and BSD licensed code:
 * https://github.com/kjur/jsjws/blob/master/rsa.js
 * http://webrsa.cvs.sourceforge.net/viewvc/webrsa/Client/RSAES-OAEP.js?content-type=text%2Fplain

 * Official documentation: http://www.rsa.com/rsalabs/node.asp?id=2125
 */
(function() {
/* ########## Begin module implementation ########## */
function initModule(forge) {

// shortcut for PKCS#12 API
var pkcs1 = forge.pkcs1 = forge.pkcs1 || {};

/**
 * RSAES-OAEP-ENCRYPT message (M) using key, with optional label (L) and seed.
 */
pkcs1.rsa_oaep_encrypt = function(key, message, label, seed) {
  // hash function hard-coded to SHA-1
  var md = forge.md.sha1.create();

  // compute length in bytes and check output
  var keyLength = Math.ceil(key.n.bitLength() / 8);
  var maxLength = keyLength - 2 * md.digestLength - 2;
  if (message.length > maxLength) {
    throw new Error("input message too long (max: " + maxLength +
        " message: " + message.length + ")");
  }

  if (!label) label = '';
  md.update(label);
  var lHash = md.digest();

  var PS = '';
  var PS_length = maxLength - message.length;
  for (var i = 0; i < PS_length; i++) {
    PS += '\x00';
  }

  var DB = lHash.getBytes() + PS + '\x01' + message;

  if (!seed) {
    seed = forge.random.getBytes(md.digestLength);
  } else if (seed.length != md.digestLength) {
    throw new Error("Invalid seed");
  }

  var dbMask = rsa_mgf1(seed, keyLength - md.digestLength - 1, md);
  var maskedDB = forge.util.xorBytes(DB, dbMask, DB.length);

  var seedMask = rsa_mgf1(maskedDB, md.digestLength, md);
  var maskedSeed = forge.util.xorBytes(seed, seedMask, seed.length);

  var EM = '\x00' + maskedSeed + maskedDB;

  // true = public key; do not pad
  var C = forge.pki.rsa.encrypt(EM, key, true);
  return C;
};

/**
 * RSAES-OAEP-DECRYPT ciphertext (C) using key, with optional label (L).
 */
pkcs1.rsa_oaep_decrypt = function(key, ciphertext, label) {
  // compute length in bytes and check output
  var keyLength = Math.ceil(key.n.bitLength() / 8);

  if (ciphertext.length != keyLength) {
    throw new Error('Decryption error: invalid ciphertext length');
  }

  // hash function hard-coded to SHA-1
  var md = forge.md.sha1.create();

  if (keyLength < 2 * md.digestLength + 2) {
    throw new Error('Decryption error: key too short for the hash function');
  }

  // false = private key operation; false = no padding
  var EM = forge.pki.rsa.decrypt(ciphertext, key, false, false);

  if (!label) label = '';
  md.update(label);
  var lHash = md.digest().getBytes();

  // Split the message into its parts
  var y = EM.charAt(0);
  var maskedSeed = EM.substring(1, md.digestLength + 1);
  var maskedDB = EM.substring(1 + md.digestLength);

  var seedMask = rsa_mgf1(maskedDB, md.digestLength, md);
  var seed = forge.util.xorBytes(maskedSeed, seedMask, maskedSeed.length);

  var dbMask = rsa_mgf1(seed, keyLength - md.digestLength - 1, md);
  var db = forge.util.xorBytes(maskedDB, dbMask, maskedDB.length);

  var lHashPrime = db.substring(0, md.digestLength);

  // constant time check that all values match what is expected
  var error = y != '\x00';

  // constant time check lHash vs lHashPrime
  for (var i = 0; i < md.digestLength; i++) {
    error |= (lHash.charAt(i) != lHashPrime.charAt(i));
  }

  // "Constant time" find the 0x1 byte separating the padding (zeros) from the message
  // TODO: It must be possible to do this in a better/smarter way?
  var in_ps = 1;
  var index = md.digestLength;
  for (var j = md.digestLength; j < db.length; j++) {
    var code = db.charCodeAt(j);

    var is_0 = (code & 0x1) ^ 0x1;

    // non-zero if not 0 or 1 in the ps section
    var error_mask = in_ps ? 0xfffe : 0x0000;
    error |= (code & error_mask);

    // latch in_ps to zero after we find 0x1
    in_ps = in_ps & is_0;
    index += in_ps;
  }

  if (error || db.charCodeAt(index) != 0x1) {
    throw new Error("Decryption error: invalid padding");
  }
  return db.substring(index + 1);
};

function rsa_mgf1(seed, maskLength, hash) {
  var t = '';
  var count = Math.ceil(maskLength / hash.digestLength);
  for (var i = 0; i < count; i++) {
    var c = String.fromCharCode((i >> 24) & 0xFF, (i >> 16) & 0xFF, (i >> 8) & 0xFF, i & 0xFF);
    hash.start();
    hash.update(seed + c);
    t += hash.digest().getBytes();
  }

  return t.substring(0, maskLength);
}

} // end module implementation

/* ########## Begin module wrapper ########## */
var name = 'pkcs1';
var deps = [
  './random',
  './rsa',
  './sha1'
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
if(nodeDefine || typeof define === 'function') {
  // define module AMD style
  (nodeDefine || define)(['require', 'module'].concat(deps),
  function(require, module) {
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
  });
}
})();
