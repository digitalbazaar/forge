var assert = require('assert');
var forge = require('../js/forge');

console.log('Generating 512-bit private key...');
var keys = forge.pki.rsa.generateKeyPair(512);
var pem1 = forge.pki.privateKeyToPem(keys.privateKey);
console.log('Private key:\n' + pem1 );

console.log('Encrypting private key with password "password"...');
var pem2 = forge.pki.encryptRsaPrivateKey(
  keys.privateKey, 'password', {'encAlg': 'aes128'});
console.log('Encrypted private key:\n' + pem2);

console.log('Decrypting private key...');
var privateKey = forge.pki.decryptRsaPrivateKey(pem2, 'password');
var pem3 = forge.pki.privateKeyToPem(privateKey);
console.log('Decrypted private key:\n' + pem3);

assert(pem1 === pem3);
console.log('Keys match. SUCCESS.');