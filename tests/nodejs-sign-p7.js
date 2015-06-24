var forge = require('../js/forge');

try {
  // create PKCS#7 signed data
  var p7 = forge.pkcs7.createSignedData();
  p7.content = forge.util.createBuffer('Some content to be signed.', 'utf8');
  var signers = ['a', 'b'];
  for(var i = 0; i < signers.length; ++i) {
    var signer = createSigner(signers[i]);
    p7.addCertificate(signer.certificate);
    p7.addSigner({
      key: signer.keys.privateKey,
      certificate: signer.certificate,
      digestAlgorithm: forge.pki.oids.sha256,
      authenticatedAttributes: [{
        type: forge.pki.oids.contentType,
        value: forge.pki.oids.data
      }, {
        type: forge.pki.oids.messageDigest
        // value will be auto-populated at signing time
      }, {
        type: forge.pki.oids.signingTime,
        // value will be auto-populated at signing time
        //value: new Date('Jan 1, 2050 00:00:00Z')
      }]
    });
  }

  p7.sign();

  var pem = forge.pkcs7.messageToPem(p7);
  console.log('Signed PKCS #7 message:\n' + pem);
} catch(ex) {
  if(ex.stack) {
    console.log(ex.stack);
  } else {
    console.log('Error', ex);
  }
}

function createSigner(name) {
  console.log('Creating signer "' + name + '"...');

  // generate a keypair
  console.log('Generating 1024-bit key-pair...');
  var keys = forge.pki.rsa.generateKeyPair(1024);
  console.log('Key-pair created:');
  console.log(forge.pki.privateKeyToPem(keys.privateKey));
  console.log(forge.pki.publicKeyToPem(keys.publicKey));

  // create a certificate
  var certificate = createCertificate(name, keys);
  console.log('Signer "' + name + '" created.');

  return {
    name: name,
    keys: keys,
    certificate: certificate
  };
}

function createCertificate(name, keys) {
  // create a certificate
  console.log('Creating self-signed certificate...');
  var cert = forge.pki.createCertificate();
  cert.publicKey = keys.publicKey;
  cert.serialNumber = '01';
  cert.validity.notBefore = new Date();
  cert.validity.notAfter = new Date();
  cert.validity.notAfter.setFullYear(cert.validity.notBefore.getFullYear() + 1);
  var attrs = [{
    name: 'commonName',
    value: name
  }, {
    name: 'countryName',
    value: 'US'
  }, {
    shortName: 'ST',
    value: 'Virginia'
  }, {
    name: 'localityName',
    value: 'Blacksburg'
  }, {
    name: 'organizationName',
    value: 'Test'
  }, {
    shortName: 'OU',
    value: 'Test'
  }];
  cert.setSubject(attrs);
  cert.setIssuer(attrs);
  cert.setExtensions([{
    name: 'basicConstraints',
    cA: true
  }, {
    name: 'keyUsage',
    keyCertSign: true,
    digitalSignature: true,
    nonRepudiation: true,
    keyEncipherment: true,
    dataEncipherment: true
  }, {
    name: 'subjectAltName',
    altNames: [{
      type: 6, // URI
      value: 'http://example.org/webid#me'
    }]
  }]);

  // self-sign certificate
  cert.sign(keys.privateKey);
  console.log('Certificate created: \n' + forge.pki.certificateToPem(cert));

  return cert;
}
