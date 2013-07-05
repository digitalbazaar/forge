var assert = require('assert');
var forge = require('../js/forge');

console.log('Generating 512-bit private key...');
var keys = forge.pki.rsa.generateKeyPair(512);
var pem1 = forge.pki.privateKeyToPem(keys.privateKey);
console.log('Private key:\n' + pem1);

function encrypt(keys, algorithm) {
  console.log('Encrypting private key with algorithm "' + algorithm +
    '" and password "password"...');
  var pem2 = forge.pki.encryptRsaPrivateKey(
    keys.privateKey, 'password', {algorithm: algorithm});
  console.log('Encrypted private key:\n' + pem2);

  console.log('Decrypting private key...');
  var privateKey = forge.pki.decryptRsaPrivateKey(pem2, 'password');
  var pem3 = forge.pki.privateKeyToPem(privateKey);
  console.log('Decrypted private key:\n' + pem3);

  assert(pem1 === pem3);
}

encrypt(keys, 'aes128');
encrypt(keys, 'aes192');
encrypt(keys, 'aes256');
encrypt(keys, '3des');

console.log('Keys match. SUCCESS.');