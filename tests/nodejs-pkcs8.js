var sys = require('sys');
var forge = require('../js/forge');

sys.puts('Generating 512-bit private key...');
var keys = forge.pki.rsa.generateKeyPair(512);
var pem1 = forge.pki.privateKeyToPem(keys.privateKey);
sys.puts('Private key:\n' + pem1 + '\n');

sys.puts('Encrypting private key with password "password"...');
var pem2 = forge.pki.encryptRsaPrivateKey(
   keys.privateKey, 'password', {'encAlg': 'aes128'});
sys.puts('Encrypted private key:\n' + pem2 + '\n');

sys.puts('Decrypting private key...');
var privateKey = forge.pki.decryptRsaPrivateKey(pem2, 'password');
var pem3 = forge.pki.privateKeyToPem(privateKey);
sys.puts('Decrypted private key:\n' + pem3 + '\n');

if(pem1 === pem3)
{
   require('sys').puts('Keys match. PASS');
}
else
{
   require('sys').puts('Keys DO NOT match. FAIL');
}
