/**
 * A Javascript implementation of AES Cipher Suites for TLS.
 *
 * @author Dave Longley
 *
 * Copyright (c) 2009-2013 Digital Bazaar, Inc.
 *
 */
(function() {
/* ########## Begin module implementation ########## */
function initModule(forge) {

var tls = forge.tls;

/**
 * Supported cipher suites.
 */
tls.CipherSuites['TLS_RSA_WITH_AES_128_CBC_SHA'] = {
  id: [0x00,0x2f],
  name: 'TLS_RSA_WITH_AES_128_CBC_SHA',
  initSecurityParameters: function(sp) {
    sp.bulk_cipher_algorithm = tls.BulkCipherAlgorithm.aes;
    sp.cipher_type = tls.CipherType.block;
    sp.enc_key_length = 16;
    sp.block_length = 16;
    sp.fixed_iv_length = 16;
    sp.record_iv_length = 16;
    sp.mac_algorithm = tls.MACAlgorithm.hmac_sha1;
    sp.mac_length = 20;
    sp.mac_key_length = 20;
  },
  initConnectionState: initConnectionState
};
tls.CipherSuites['TLS_RSA_WITH_AES_256_CBC_SHA'] = {
  id: [0x00,0x35],
  name: 'TLS_RSA_WITH_AES_256_CBC_SHA',
  initSecurityParameters: function(sp) {
    sp.bulk_cipher_algorithm = tls.BulkCipherAlgorithm.aes;
    sp.cipher_type = tls.CipherType.block;
    sp.enc_key_length = 32;
    sp.block_length = 16;
    sp.fixed_iv_length = 16;
    sp.record_iv_length = 16;
    sp.mac_algorithm = tls.MACAlgorithm.hmac_sha1;
    sp.mac_length = 20;
    sp.mac_key_length = 20;
  },
  initConnectionState: initConnectionState
};

function initConnectionState(state, c, sp) {
  var client = (c.entity === forge.tls.ConnectionEnd.client);

  // cipher setup
  state.read.cipherState = {
    init: false,
    cipher: forge.aes.createDecryptionCipher(client ?
      sp.keys.server_write_key : sp.keys.client_write_key),
    iv: client ? sp.keys.server_write_IV : sp.keys.client_write_IV
  };
  state.write.cipherState = {
    init: false,
    cipher: forge.aes.createEncryptionCipher(client ?
      sp.keys.client_write_key : sp.keys.server_write_key),
    iv: client ? sp.keys.client_write_IV : sp.keys.server_write_IV
  };
  state.read.cipherFunction = decrypt_aes_cbc_sha1;
  state.write.cipherFunction = encrypt_aes_cbc_sha1;

  // MAC setup
  state.read.macLength = state.write.macLength = sp.mac_length;
  state.read.macFunction = state.write.macFunction = tls.hmac_sha1;
};

/**
 * Encrypts the TLSCompressed record into a TLSCipherText record using AES
 * in CBC mode.
 *
 * @param record the TLSCompressed record to encrypt.
 * @param s the ConnectionState to use.
 *
 * @return true on success, false on failure.
 */
function encrypt_aes_cbc_sha1(record, s) {
  var rval = false;

  // append MAC to fragment, update sequence number
  var mac = s.macFunction(s.macKey, s.sequenceNumber, record);
  record.fragment.putBytes(mac);
  s.updateSequenceNumber();

  // TLS 1.1 & 1.2 use an explicit IV every time to protect against
  // CBC attacks
  var iv;
  if(record.version.minor > 1) {
    iv = forge.random.getBytes(16);
  }
  else {
    // use the pre-generated IV when initializing for TLS 1.0, otherwise use
    // the residue from the previous encryption
    iv = s.cipherState.init ? null : s.cipherState.iv;
  }
  s.cipherState.init = true;

  // start cipher
  var cipher = s.cipherState.cipher;
  cipher.start(iv);

  // TLS 1.1 & 1.2 write IV into output
  if(record.version.minor > 1) {
    cipher.output.putBytes(iv);
  }

  // do encryption (default padding is appropriate)
  cipher.update(record.fragment);
  if(cipher.finish(encrypt_aes_cbc_sha1_padding)) {
    // set record fragment to encrypted output
    record.fragment = cipher.output;
    record.length = record.fragment.length();
    rval = true;
  }

  return rval;
}

/**
 * Handles padding for aes_cbc_sha1 in encrypt mode.
 *
 * @param blockSize the block size.
 * @param input the input buffer.
 * @param decrypt true in decrypt mode, false in encrypt mode.
 *
 * @return true on success, false on failure.
 */
function encrypt_aes_cbc_sha1_padding(blockSize, input, decrypt) {
  /* The encrypted data length (TLSCiphertext.length) is one more than the sum
   of SecurityParameters.block_length, TLSCompressed.length,
   SecurityParameters.mac_length, and padding_length.

   The padding may be any length up to 255 bytes long, as long as it results in
   the TLSCiphertext.length being an integral multiple of the block length.
   Lengths longer than necessary might be desirable to frustrate attacks on a
   protocol based on analysis of the lengths of exchanged messages. Each uint8
   in the padding data vector must be filled with the padding length value.

   The padding length should be such that the total size of the
   GenericBlockCipher structure is a multiple of the cipher's block length.
   Legal values range from zero to 255, inclusive. This length specifies the
   length of the padding field exclusive of the padding_length field itself.

   This is slightly different from PKCS#7 because the padding value is 1
   less than the actual number of padding bytes if you include the
   padding_length uint8 itself as a padding byte. */
  if(!decrypt) {
    // get the number of padding bytes required to reach the blockSize and
    // subtract 1 for the padding value (to make room for the padding_length
    // uint8)
    var padding = blockSize - (input.length() % blockSize);
    input.fillWithByte(padding - 1, padding);
  }
  return true;
}

/**
 * Handles padding for aes_cbc_sha1 in decrypt mode.
 *
 * @param blockSize the block size.
 * @param output the output buffer.
 * @param decrypt true in decrypt mode, false in encrypt mode.
 *
 * @return true on success, false on failure.
 */
function decrypt_aes_cbc_sha1_padding(blockSize, output, decrypt) {
  var rval = true;
  if(decrypt) {
    /* The last byte in the output specifies the number of padding bytes not
      including itself. Each of the padding bytes has the same value as that
      last byte (known as the padding_length). Here we check all padding
      bytes to ensure they have the value of padding_length even if one of
      them is bad in order to ward-off timing attacks. */
    var len = output.length();
    var paddingLength = output.last();
    for(var i = len - 1 - paddingLength; i < len - 1; ++i) {
      rval = rval && (output.at(i) == paddingLength);
    }
    if(rval) {
      // trim off padding bytes and last padding length byte
      output.truncate(paddingLength + 1);
    }
  }
  return rval;
}

/**
 * Decrypts a TLSCipherText record into a TLSCompressed record using
 * AES in CBC mode.
 *
 * @param record the TLSCipherText record to decrypt.
 * @param s the ConnectionState to use.
 *
 * @return true on success, false on failure.
 */
function decrypt_aes_cbc_sha1(record, s) {
  var rval = false;

  // TODO: TLS 1.1 & 1.2 use an explicit IV every time to protect against
  // CBC attacks
  //var iv = record.fragment.getBytes(16);

  // use pre-generated IV when initializing for TLS 1.0, otherwise use the
  // residue from the previous decryption
  var iv = s.cipherState.init ? null : s.cipherState.iv;
  s.cipherState.init = true;

  // start cipher
  var cipher = s.cipherState.cipher;
  cipher.start(iv);

  // do decryption
  cipher.update(record.fragment);
  rval = cipher.finish(decrypt_aes_cbc_sha1_padding);

  // even if decryption fails, keep going to minimize timing attacks

  // decrypted data:
  // first (len - 20) bytes = application data
  // last 20 bytes          = MAC
  var macLen = s.macLength;

  // create a zero'd out mac
  var mac = '';
  for(var i = 0; i < macLen; ++i) {
    mac += String.fromCharCode(0);
  }

  // get fragment and mac
  var len = cipher.output.length();
  if(len >= macLen) {
    record.fragment = cipher.output.getBytes(len - macLen);
    mac = cipher.output.getBytes(macLen);
  }
  // bad data, but get bytes anyway to try to keep timing consistent
  else {
    record.fragment = cipher.output.getBytes();
  }
  record.fragment = forge.util.createBuffer(record.fragment);
  record.length = record.fragment.length();

  // see if data integrity checks out, update sequence number
  var mac2 = s.macFunction(s.macKey, s.sequenceNumber, record);
  s.updateSequenceNumber();
  rval = (mac2 === mac) && rval;
  return rval;
}

} // end module implementation

/* ########## Begin module wrapper ########## */
var name = 'aesCipherSuites';
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
define(['require', 'module', './aes', './tls'], function() {
  defineFunc.apply(null, Array.prototype.slice.call(arguments, 0));
});
})();
