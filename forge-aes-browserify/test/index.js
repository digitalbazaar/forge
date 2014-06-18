'use strict';

var test = require('tape'),
    forge = require('../index');

var Demo = {
    encrypt: function(password, data) {
        var salt = forge.random.getBytesSync(128),
            iv = forge.random.getBytesSync(16),
            key = forge.pbkdf2(password, salt, 100, 16),
            cipher = forge.aes.createEncryptionCipher(key, 'CBC');

        cipher.start(iv);
        cipher.update(forge.util.createBuffer(data), 'utf8');
        cipher.finish();

        return {
            secret: cipher.output.toHex(),
            salt: forge.util.bytesToHex(salt),
            iv: forge.util.bytesToHex(iv)
        };
    },

    decrypt: function(password, secret, salt, iv) {
        var key = forge.pbkdf2(password, forge.util.hexToBytes(salt), 100, 16),
            encrypted = forge.util.createBuffer(forge.util.hexToBytes(secret)),
            cipher = forge.aes.createDecryptionCipher(key, 'CBC');

        cipher.start(forge.util.hexToBytes(iv));
        cipher.update(encrypted);
        cipher.finish();

        return cipher.output;
    },
};

test('Should be able to encrypt and decrypt', function(assert) {
    var password = 'SECRET',
        secret = 'Lorem ipsum sit amet';

    var crypted = Demo.encrypt(password, secret);
    var decrypted = Demo.decrypt(password, crypted.secret, crypted.salt, crypted.iv);

    assert.equal(decrypted.data, secret);
    assert.end();
});
