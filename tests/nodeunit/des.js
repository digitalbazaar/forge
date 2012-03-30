var forge = require('../../js/forge');

/**
 * Test encryption with DES3 cipher in CBC mode.
 *
 * Reference value generatable wih OpenSSL like this:
 * openssl enc -des3 -K a1c06b381adf36517e84575552777779da5e3d9f994b05b5 -iv 818bcf76efc59662 -nosalt
 */
exports.testEncryptDES3CBC = function(test) {
   key = 'a1c06b381adf36517e84575552777779da5e3d9f994b05b5';
   iv = '818bcf76efc59662';

   key = forge.util.createBuffer(forge.util.hexToBytes(key));
   iv = forge.util.createBuffer(forge.util.hexToBytes(iv));

   cipher = forge.des.createEncryptionCipher(key);
   cipher.start(iv.copy());
   cipher.update(forge.util.createBuffer('foobar'));
   cipher.finish();
   test.equal(cipher.output.toHex(), '209225f7687ca0b2');

   // try restart
   cipher.start(iv.copy());
   cipher.update(forge.util.createBuffer('foobar,,'));
   cipher.finish();
   test.equal(cipher.output.toHex(), '57156174c48dfc37293831bf192a6742');

   test.done();
}

/**
 * Test encryption with DES3 cipher in ECB mode.
 *
 * Reference value generatable wih OpenSSL like this:
 * openssl enc -des-ede3 -K a1c06b381adf36517e84575552777779da5e3d9f994b05b5 -nosalt 
 */
exports.testEncryptDES3ECB = function(test) {
   key = 'a1c06b381adf36517e84575552777779da5e3d9f994b05b5';
   key = forge.util.createBuffer(forge.util.hexToBytes(key));

   cipher = forge.des.createEncryptionCipher(key);
   cipher.start(null);
   cipher.update(forge.util.createBuffer('foobar'));
   cipher.finish();
   test.equal(cipher.output.toHex(), 'fce8b1ee8c6440d1');

   test.done();
}

/**
 * Test encryption with DES cipher in CBC mode.
 *
 * Reference value generatable wih OpenSSL like this:
 * openssl enc -des -K a1c06b381adf3651 -iv 818bcf76efc59662 -nosalt
 */
exports.testEncryptDES_CBC = function(test) {
   key = 'a1c06b381adf3651';
   iv = '818bcf76efc59662';

   key = forge.util.createBuffer(forge.util.hexToBytes(key));
   iv = forge.util.createBuffer(forge.util.hexToBytes(iv));

   cipher = forge.des.createEncryptionCipher(key);
   cipher.start(iv.copy());
   cipher.update(forge.util.createBuffer('foobar'));
   cipher.finish();
   test.equal(cipher.output.toHex(), '3261e5839a990454');

   test.done();
}

/**
 * Test encryption with DES cipher in ECB mode.
 *
 * Reference value generatable wih OpenSSL like this:
 * openssl enc -des-ecb -K a1c06b381adf3651 -nosalt
 */
exports.testEncryptDES_ECB = function(test) {
   key = 'a1c06b381adf3651';
   key = forge.util.createBuffer(forge.util.hexToBytes(key));

   cipher = forge.des.createEncryptionCipher(key);
   cipher.start(null);
   cipher.update(forge.util.createBuffer('foobar'));
   cipher.finish();
   test.equal(cipher.output.toHex(), 'b705ffcf3dff06b3');

   test.done();
}

/**
 * Test decryption with DES3 cipher in CBC mode.
 *
 * Reference value generatable wih OpenSSL like this:
 * openssl enc -d -des3 -K a1c06b381adf36517e84575552777779da5e3d9f994b05b5 -iv 818bcf76efc59662 -nosalt
 */
exports.testDecryptDES3CBC = function(test) {
   key = 'a1c06b381adf36517e84575552777779da5e3d9f994b05b5';
   iv = '818bcf76efc59662';
   ciphertext = '209225f7687ca0b2';

   key = forge.util.createBuffer(forge.util.hexToBytes(key));
   iv = forge.util.createBuffer(forge.util.hexToBytes(iv));
   ciphertext = forge.util.createBuffer(forge.util.hexToBytes(ciphertext));

   cipher = forge.des.createDecryptionCipher(key);
   cipher.start(iv.copy());
   cipher.update(ciphertext);
   cipher.finish();
   test.equal(cipher.output.getBytes(), 'foobar');

   // try restart
   ciphertext = '57156174c48dfc37293831bf192a6742';
   ciphertext = forge.util.createBuffer(forge.util.hexToBytes(ciphertext));
   cipher.start(iv.copy());
   cipher.update(ciphertext);
   cipher.finish();
   test.equal(cipher.output.getBytes(), 'foobar,,');

   test.done();
}

/**
 * Test decryption with DES3 cipher in ECB mode.
 *
 * Reference value generatable wih OpenSSL like this:
 * openssl enc -d -des-ede3 -K a1c06b381adf36517e84575552777779da5e3d9f994b05b5 -nosalt 
 */
exports.testDecryptDES3ECB = function(test) {
   key = 'a1c06b381adf36517e84575552777779da5e3d9f994b05b5';
   ciphertext = 'fce8b1ee8c6440d1';

   key = forge.util.createBuffer(forge.util.hexToBytes(key));
   ciphertext = forge.util.createBuffer(forge.util.hexToBytes(ciphertext));

   cipher = forge.des.createDecryptionCipher(key);
   cipher.start(null);
   cipher.update(ciphertext);
   cipher.finish();
   test.equal(cipher.output.getBytes(), 'foobar');

   test.done();
}

/**
 * Test decryption with DES cipher in CBC mode.
 *
 * Reference value generatable wih OpenSSL like this:
 * openssl enc -d -des -K a1c06b381adf3651 -iv 818bcf76efc59662 -nosalt
 */
exports.testDecryptDES_CBC = function(test) {
   key = 'a1c06b381adf3651';
   iv = '818bcf76efc59662';
   ciphertext = '3261e5839a990454';

   key = forge.util.createBuffer(forge.util.hexToBytes(key));
   iv = forge.util.createBuffer(forge.util.hexToBytes(iv));
   ciphertext = forge.util.createBuffer(forge.util.hexToBytes(ciphertext));

   cipher = forge.des.createDecryptionCipher(key);
   cipher.start(iv.copy());
   cipher.update(ciphertext);
   cipher.finish();
   test.equal(cipher.output.getBytes(), 'foobar');

   test.done();
}

/**
 * Test decryption with DES cipher in ECB mode.
 *
 * Reference value generatable wih OpenSSL like this:
 * openssl enc -d -des-ecb -K a1c06b381adf3651 -nosalt
 */
exports.testDecryptDES_ECB = function(test) {
   key = 'a1c06b381adf3651';
   ciphertext = 'b705ffcf3dff06b3';

   key = forge.util.createBuffer(forge.util.hexToBytes(key));
   ciphertext = forge.util.createBuffer(forge.util.hexToBytes(ciphertext));

   cipher = forge.des.createDecryptionCipher(key);
   cipher.start(null);
   cipher.update(ciphertext);
   cipher.finish();
   test.equal(cipher.output.getBytes(), 'foobar');

   test.done();
}
