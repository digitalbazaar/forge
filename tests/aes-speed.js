var forge = require('../js/forge');

aes_128('GCM');

function aes_128(mode) {
  var size = 4096;
  var key = forge.random.getBytes(16);
  var iv = forge.random.getBytes(mode === 'GCM' ? 12 : 16);
  var plain = forge.util.createBuffer().fillWithByte(0, size);

  // run for 5 seconds
  var start = Date.now();

  var now;
  var totalEncrypt = 0;
  var totalDecrypt = 0;
  var count = 0;
  var passed = 0;
  while(passed < 5000) {
    var input = forge.util.createBuffer(plain);

    // encrypt, only measuring update() and finish()
    var cipher = forge.aes.createEncryptionCipher(key, mode);
    cipher.start(iv);
    now = Date.now();
    cipher.update(input);
    cipher.finish();
    totalEncrypt += Date.now() - now;

    var ciphertext = cipher.output;
    var tag = cipher.tag;

    // decrypt, only measuring update() and finish()
    cipher = forge.aes.createDecryptionCipher(key, mode);
    cipher.start(iv, {tag: tag});
    now = Date.now();
    cipher.update(ciphertext);
    if(!cipher.finish()) {
      throw new Error('Decryption error.');
    }
    totalDecrypt += Date.now() - now;

    ++count;
    passed = Date.now() - start;
  }

  count = count * size / 1000;
  totalEncrypt /= 1000;
  totalDecrypt /= 1000;

  console.log('times in 1000s of bytes/sec processed.');
  console.log('encrypt: ' + (count / totalEncrypt) + ' k/sec');
  console.log('decrypt: ' + (count / totalDecrypt) + ' k/sec');
}
