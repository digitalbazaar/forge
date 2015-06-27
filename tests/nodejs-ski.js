var forge = require('../js/forge');

//Create a keypair
var keys = forge.pki.rsa.generateKeyPair(1024);

//Create a PKCS7 message
var p7 = forge.pkcs7.createEnvelopedData();

//Set recipient as subjectKeyIdentifier
var someIdentifier = "ABC123";
p7.addRecipient({ subjectKeyIdentifier: someIdentifier, publicKey: keys.publicKey})

//Set Content
p7.content = forge.util.createBuffer('This is the expected output');

// encrypt
p7.encrypt();

//Convert to pem
var pem = forge.pkcs7.messageToPem(p7);

//Convert back to message
var p7 = forge.pkcs7.messageFromPem(pem);

//Find recipient by key
var recipient = p7.findRecipient(someIdentifier);

// decrypt
p7.decrypt(p7.recipients[0], keys.privateKey);

//Show the result
console.log(p7.content.data);