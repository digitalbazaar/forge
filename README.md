# Forge

[![Build Status][travis-ci-png]][travis-ci-site]
[travis-ci-png]: https://travis-ci.org/digitalbazaar/forge.png?branch=master
[travis-ci-site]: https://travis-ci.org/digitalbazaar/forge

A native implementation of [TLS][] (and various other cryptographic tools) in
[JavaScript][].

## Introduction

The Forge software is a fully native implementation of the [TLS][] protocol in
JavaScript as well as a set of tools for developing Web Apps that utilize many
network resources.

## Getting Started
------------------

### Node.js ###

If you want to use forge with [node.js][], it is available through `npm`:

https://npmjs.org/package/node-forge

Installation:

    npm install node-forge

You can then use forge as a regular module:

    var forge = require('node-forge');

### Requirements ###

* General
  * Optional: GNU autotools for the build infrastructure if using Flash.
* Building a Browser Bundle:
  * nodejs
  * npm
* Testing
  * nodejs
  * Optional: Python and OpenSSL development environment to build
  * a special SSL module with session cache support for testing with flash.
  * http://www.python.org/dev/
  * http://www.openssl.org/
  * Debian users should install python-dev and libssl-dev.
* Optional: Flash
  * A pre-built SocketPool.swf is included.
  * Adobe Flex 3 SDK to build the Flash socket code.
  * http://opensource.adobe.com/wiki/display/flexsdk/

### Building a browser bundle ###

To create a minimized JavaScript bundle, run the following:

```
npm install
npm run minify
```

This will create a single minimized file that can be included in
the browser:

```
js/forge.min.js
```

Include the file via:

```html
<script src="js/forge.min.js"></script>
```

To create a single non-minimized file that can be included in
the browser:

```
npm install
npm run bundle
```

This will create:

```
js/forge.bundle.js
```

Include the file via:

```html
<script src="js/forge.bundle.js"></script>
```

The above bundles will synchronously create a global 'forge' object.

Keep in mind that these bundles will not include any WebWorker
scripts (eg: prime.worker.js) or their dependencies, so these will
need to be accessible from the browser if any WebWorkers are used.

### Testing with NodeJS & RequireJS ###

A test server for [node.js][] can be found at `./nodejs`. The following are included:

  * Example of how to use `forge` within NodeJS in the form of a [mocha](http://visionmedia.github.io/mocha/) test.
  * Example of how to serve `forge` to the browser using [RequireJS](http://requirejs.org/).

To run:

    cd nodejs
    npm install
    npm test
    npm start


### Old build system that includes flash support ###

To build the whole project, including Flash, run the following:

    $ ./build-setup
    $ make

This will create the SWF, symlink all the JavaScript files, and build a Python
SSL module for testing. To see configure options, run `./configure --help`.

### Old test system including flash support ###

A test server is provided which can be run in TLS mode and non-TLS mode. Use
the --help option to get help for configuring ports. The server will print out
the local URL you can vist to run tests.

Some of the simplier tests should be run with just the non-TLS server::

    $ ./tests/server.py

More advanced tests need TLS enabled::

    $ ./tests/server.py --tls

## Documentation
----------------

### Transports

* [TLS](#tls)
* [HTTP](#http)
* [XHR](#xhr)
* [Sockets](#socket)

### Ciphers

* [AES](#aes)
* [DES](#des)
* [RC2](#rc2)

### PKI

* [RSA](#rsa)
* [X.509](#x509)
* [PKCS#5](#pkcs5)
* [PKCS#7](#pkcs7)
* [PKCS#8](#pkcs8)
* [PKCS#10](#pkcs10)
* [PKCS#12](#pkcs12)
* [ASN.1](#asn)

### Message Digests

* [SHA1](#sha1)
* [SHA256](#sha256)
* [MD5](#md5)
* [HMAC](#hmac)

### Utilities

* [PRNG](#prng)
* [Tasks](#task)
* [Utilities](#util)
* [Logging](#log)
* [Debugging](#debug)
* [Flash Socket Policy Module](#fsp)

---------------------------------------

If at any time you wish to disable the use of native code, where available,
for particular forge features like its secure random number generator, you
may set the ```disableNativeCode``` flag on ```forge``` to ```true```. It
is not recommended that you set this flag as native code is typically more
performant and may have stronger security properties. It may be useful to
set this flag to test certain features that you plan to run in environments
that are different from your testing environment.

To disable native code when including forge in the browser:

```js
forge = {disableNativeCode: true};
// now include other files
```

To disable native code when using node.js:

```js
var forge = require('node-forge')({disableNativeCode: true});
```

---------------------------------------
## Transports

<a name="tls" />
### TLS

Provides a native javascript client and server-side [TLS][] implementation.

__Examples__

```js
// create TLS client
var client = forge.tls.createConnection({
  server: false,
  caStore: /* Array of PEM-formatted certs or a CA store object */,
  sessionCache: {},
  // supported cipher suites in order of preference
  cipherSuites: [
    forge.tls.CipherSuites.TLS_RSA_WITH_AES_128_CBC_SHA,
    forge.tls.CipherSuites.TLS_RSA_WITH_AES_256_CBC_SHA],
  virtualHost: 'example.com',
  verify: function(connection, verified, depth, certs) {
    if(depth === 0) {
      var cn = certs[0].subject.getField('CN').value;
      if(cn !== 'example.com') {
        verified = {
          alert: forge.tls.Alert.Description.bad_certificate,
          message: 'Certificate common name does not match hostname.'
        };
      }
    }
    return verified;
  },
  connected: function(connection) {
    console.log('connected');
    // send message to server
    connection.prepare(forge.util.encodeUtf8('Hi server!'));
  },
  /* provide a client-side cert if you want
  getCertificate: function(connection, hint) {
    return myClientCertificate;
  },
  /* the private key for the client-side cert if provided */
  getPrivateKey: function(connection, cert) {
    return myClientPrivateKey;
  },
  tlsDataReady: function(connection) {
    // TLS data (encrypted) is ready to be sent to the server
    sendToServerSomehow(connection.tlsData.getBytes());
    // if you were communicating with the server below, you'd do:
    // server.process(connection.tlsData.getBytes());
  },
  dataReady: function(connection) {
    // clear data from the server is ready
    console.log('the server sent: ' +
      forge.util.decodeUtf8(connection.data.getBytes()));
    // close connection
    connection.close();
  },
  closed: function(connection) {
    console.log('disconnected');
  },
  error: function(connection, error) {
    console.log('uh oh', error);
  }
});

// start the handshake process
client.handshake();

// when encrypted TLS data is received from the server, process it
client.process(encryptedBytesFromServer);

// create TLS server
var server = forge.tls.createConnection({
  server: true,
  caStore: /* Array of PEM-formatted certs or a CA store object */,
  sessionCache: {},
  // supported cipher suites in order of preference
  cipherSuites: [
    forge.tls.CipherSuites.TLS_RSA_WITH_AES_128_CBC_SHA,
    forge.tls.CipherSuites.TLS_RSA_WITH_AES_256_CBC_SHA],
  // require a client-side certificate if you want
  verifyClient: true,
  verify: function(connection, verified, depth, certs) {
    if(depth === 0) {
      var cn = certs[0].subject.getField('CN').value;
      if(cn !== 'the-client') {
        verified = {
          alert: forge.tls.Alert.Description.bad_certificate,
          message: 'Certificate common name does not match expected client.'
        };
      }
    }
    return verified;
  },
  connected: function(connection) {
    console.log('connected');
    // send message to client
    connection.prepare(forge.util.encodeUtf8('Hi client!'));
  },
  getCertificate: function(connection, hint) {
    return myServerCertificate;
  },
  getPrivateKey: function(connection, cert) {
    return myServerPrivateKey;
  },
  tlsDataReady: function(connection) {
    // TLS data (encrypted) is ready to be sent to the client
    sendToClientSomehow(connection.tlsData.getBytes());
    // if you were communicating with the client above you'd do:
    // client.process(connection.tlsData.getBytes());
  },
  dataReady: function(connection) {
    // clear data from the client is ready
    console.log('the client sent: ' +
      forge.util.decodeUtf8(connection.data.getBytes()));
    // close connection
    connection.close();
  },
  closed: function(connection) {
    console.log('disconnected');
  },
  error: function(connection, error) {
    console.log('uh oh', error);
  }
});

// when encrypted TLS data is received from the client, process it
server.process(encryptedBytesFromClient);
```

Connect to a TLS server using node's net.Socket:

```js
var socket = new net.Socket();

var client = forge.tls.createConnection({
  server: false,
  verify: function(connection, verified, depth, certs) {
    // skip verification for testing
    console.log('[tls] server certificate verified');
    return true;
  },
  connected: function(connection) {
    console.log('[tls] connected');
    // prepare some data to send (note that the string is interpreted as
    // 'binary' encoded, which works for HTTP which only uses ASCII, use
    // forge.util.encodeUtf8(str) otherwise
    client.prepare('GET / HTTP/1.0\r\n\r\n');
  },
  tlsDataReady: function(connection) {
    // encrypted data is ready to be sent to the server
    var data = connection.tlsData.getBytes();
    socket.write(data, 'binary'); // encoding should be 'binary'
  },
  dataReady: function(connection) {
    // clear data from the server is ready
    var data = connection.data.getBytes();
    console.log('[tls] data received from the server: ' + data);
  },
  closed: function() {
    console.log('[tls] disconnected');
  },
  error: function(connection, error) {
    console.log('[tls] error', error);
  }
});

socket.on('connect', function() {
  console.log('[socket] connected');
  client.handshake();
});
socket.on('data', function(data) {
  client.process(data.toString('binary')); // encoding should be 'binary'
});
socket.on('end', function() {
  console.log('[socket] disconnected');
});

// connect to google.com
socket.connect(443, 'google.com');

// or connect to gmail's imap server (but don't send the HTTP header above)
//socket.connect(993, 'imap.gmail.com');
```

<a name="http" />
### HTTP

Provides a native [JavaScript][] mini-implementation of an http client that
uses pooled sockets.

__Examples__

```js
// create an HTTP GET request
var request = forge.http.createRequest({method: 'GET', path: url.path});

// send the request somewhere
sendSomehow(request.toString());

// receive response
var buffer = forge.util.createBuffer();
var response = forge.http.createResponse();
var someAsyncDataHandler = function(bytes) {
  if(!response.bodyReceived) {
    buffer.putBytes(bytes);
    if(!response.headerReceived) {
      if(response.readHeader(buffer)) {
        console.log('HTTP response header: ' + response.toString());
      }
    }
    if(response.headerReceived && !response.bodyReceived) {
      if(response.readBody(buffer)) {
        console.log('HTTP response body: ' + response.body);
      }
    }
  }
};
```

<a name="xhr" />
### XHR

Provides an XmlHttpRequest implementation using forge.http as a backend.

__Examples__

```js
```

<a name="socket" />
### Sockets

Provides an interface to create and use raw sockets provided via Flash.

__Examples__

```js
```

---------------------------------------
## Ciphers

<a name="aes" />
### AES

Provides basic [AES][] encryption and decryption in CBC, CFB, OFB, or CTR mode.

__Examples__

```js
// generate a random key and IV
var key = forge.random.getBytesSync(16);
var iv = forge.random.getBytesSync(16);

// encrypt some bytes using CBC mode
// (other modes include: CFB, OFB, and CTR)
var cipher = forge.aes.createEncryptionCipher(key, 'CBC');
cipher.start(iv);
cipher.update(forge.util.createBuffer(someBytes));
cipher.finish();
var encrypted = cipher.output;
// outputs encrypted hex
console.log(encrypted.toHex());

// decrypt some bytes using CBC mode
// (other modes include: CFB, OFB, and CTR)
var cipher = forge.aes.createDecryptionCipher(key, 'CBC');
cipher.start(iv);
cipher.update(encrypted);
cipher.finish();
// outputs decrypted hex
console.log(cipher.output.toHex());

// generate a password-based 16-byte key
var salt = forge.random.getBytesSync(128);
var derivedKey = forge.pkcs5.pbkdf2('password', salt, numIterations, 16);
```

<a name="des" />
### DES

__Examples__

```js
// generate a random key and IV
var key = forge.random.getBytesSync(24);
var iv = forge.random.getBytesSync(8);

// encrypt some bytes
var cipher = forge.des.createEncryptionCipher(key);
cipher.start(iv);
cipher.update(forge.util.createBuffer(someBytes));
cipher.finish();
var encrypted = cipher.output;
// outputs encrypted hex
console.log(encrypted.toHex());

// decrypt some bytes
var cipher = forge.des.createDecryptionCipher(key);
cipher.start(iv);
cipher.update(encrypted);
cipher.finish();
// outputs decrypted hex
console.log(cipher.output.toHex());
```

<a name="rc2" />
### RC2

__Examples__

```js
// generate a random key and IV
var key = forge.random.getBytesSync(16);
var iv = forge.random.getBytesSync(8);

// encrypt some bytes
var cipher = forge.rc2.createEncryptionCipher(key);
cipher.start(iv);
cipher.update(forge.util.createBuffer(someBytes));
cipher.finish();
var encrypted = cipher.output;
// outputs encrypted hex
console.log(encrypted.toHex());

// decrypt some bytes
var cipher = forge.rc2.createDecryptionCipher(key);
cipher.start(iv);
cipher.update(encrypted);
cipher.finish();
// outputs decrypted hex
console.log(cipher.output.toHex());
```
---------------------------------------
## PKI

Provides [X.509][] certificate and RSA public and private key encoding,
decoding, encryption/decryption, and signing/verifying.

<a name="rsa" />
### RSA

__Examples__

```js
var rsa = forge.pki.rsa;

// generate an RSA key pair synchronously
var keypair = rsa.generateKeyPair({bits: 2048, e: 0x10001});

// generate an RSA key pair asynchronously (uses web workers if available)
rsa.generateKeyPair({bits: 2048, workers: 2}, function(err, keypair) {
  // keypair.privateKey, keypair.publicKey
});

// generate an RSA key pair in steps that attempt to run for a specified period
// of time on the main JS thread
var state = rsa.createKeyPairGenerationState(2048, 0x10001);
var step = function() {
  // run for 100 ms
  if(!rsa.stepKeyPairGenerationState(state, 100)) {
    setTimeout(step, 1);
  }
  else {
    // done, turn off progress indicator, use state.keys
  }
});
// turn on progress indicator, schedule generation to run
setTimeout(step);

// sign data with a private key and output DigestInfo DER-encoded bytes
var md = forge.md.sha1.create();
md.update('sign this', 'utf8');
var signature = privateKey.sign(md);

// verify data with a public key
var verified = publicKey.verify(md.digest().bytes(), signature);

// encrypt data with a public key (defaults to RSAES PKCS#1 v1.5)
var encrypted = publicKey.encrypt(bytes);

// decrypt data with a private key (defaults to RSAES PKCS#1 v1.5)
var decrypted = privateKey.decrypt(encrypted);

// encrypt data with a public key using RSAES PKCS#1 v1.5
var encrypted = publicKey.encrypt(bytes, 'RSAES-PKCS1-V1_5');

// decrypt data with a private key using RSAES PKCS#1 v1.5
var decrypted = privateKey.decrypt(encrypted, 'RSAES-PKCS1-V1_5');

// encrypt data with a public key using RSAES-OAEP
var encrypted = publicKey.encrypt(bytes, 'RSA-OAEP');

// decrypt data with a private key using RSAES-OAEP
var decrypted = privateKey.decrypt(encrypted, 'RSA-OAEP');
```

<a name="x509" />
### X.509

__Examples__

```js
var pki = forge.pki;

// convert a PEM-formatted public key to a Forge public key
var publicKey = pki.publicKeyFromPem(pem);

// convert a Forge public key to PEM-format
var pem = pki.publicKeyToPem(publicKey);

// convert an ASN.1 SubjectPublicKeyInfo to a Forge public key
var publicKey = pki.publicKeyFromAsn1(subjectPublicKeyInfo);

// convert a Forge public key to an ASN.1 SubjectPublicKeyInfo
var subjectPublicKeyInfo = pki.publicKeyToAsn1(publicKey);

// creates a CA store
var caStore = pki.createCaStore([/* PEM-encoded cert */, ...]);

// add a certificate to the CA store
caStore.addCertificate(certObjectOrPemString);

// gets the issuer (its certificate) for the given certificate
var issuerCert = caStore.getIssuer(subjectCert);

// verifies a certificate chain against a CA store
pki.verifyCertificateChain(caStore, chain, customVerifyCallback);

// signs a certificate using the given private key
cert.sign(privateKey);

// signs a certificate using SHA-256 instead of SHA-1
cert.sign(privateKey, forge.md.sha256.create());

// verifies an issued certificate using the certificates public key
var verified = issuer.verify(issued);

// generate a keypair and create an X.509v3 certificate
var keys = pki.rsa.generateKeyPair(2048);
var cert = pki.createCertificate();
cert.publicKey = keys.publicKey;
cert.serialNumber = '01';
cert.validity.notBefore = new Date();
cert.validity.notAfter = new Date();
cert.validity.notAfter.setFullYear(cert.validity.notBefore.getFullYear() + 1);
var attrs = [{
  name: 'commonName',
  value: 'example.org'
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
  name: 'extKeyUsage',
  serverAuth: true,
  clientAuth: true,
  codeSigning: true,
  emailProtection: true,
  timeStamping: true
}, {
  name: 'nsCertType',
  client: true,
  server: true,
  email: true,
  objsign: true,
  sslCA: true,
  emailCA: true,
  objCA: true
}, {
  name: 'subjectAltName',
  altNames: [{
    type: 6, // URI
    value: 'http://example.org/webid#me'
  }, {
    type: 7, // IP
    ip: '127.0.0.1'
  }]
}, {
  name: 'subjectKeyIdentifier'
}]);
// self-sign certificate
cert.sign(keys.privateKey);

// convert a Forge certificate to PEM
var pem = pki.certificateToPem(cert);

// convert a Forge certificate from PEM
var cert = pki.certificateFromPem(pem);

// convert an ASN.1 X.509x3 object to a Forge certificate
var cert = pki.certificateFromAsn1(obj);

// convert a Forge certificate to an ASN.1 X.509v3 object
var asn1Cert = pki.certificateToAsn1(cert);
```

<a name="pkcs5" />
### PKCS#5

Provides the password-based key-derivation function from [PKCS#5][].

__Examples__

```js
// generate a password-based 16-byte key
var salt = forge.random.getBytesSync(128);
var derivedKey = forge.pkcs5.pbkdf2('password', salt, numIterations, 16);
```

<a name="pkcs7" />
### PKCS#7

Provides cryptographically protected messages from [PKCS#7][].

__Examples__

```js
// convert a message from PEM
var p7 = forge.pkcs7.messageFromPem(pem);
// look at p7.recipients

// find a recipient by the issuer of a certificate
var recipient = p7.findRecipient(cert);

// decrypt
p7.decrypt(p7.recipients[0], privateKey);

// create a p7 enveloped message
var p7 = forge.pkcs7.createEnvelopedData();

// add a recipient
var cert = forge.pki.certificateFromPem(certPem);
p7.addRecipient(cert);

// set content
p7.content = forge.util.createBuffer('Hello');

// encrypt
p7.encrypt();

// convert message to PEM
var pem = forge.pkcs7.messageToPem(p7);

// create a degenerate PKCS#7 certificate container
// (CRLs not currently supported, only certificates)
var p7 = forge.pkcs7.createSignedData();
p7.addCertificate(certOrCertPem1);
p7.addCertificate(certOrCertPem2);
var pem = forge.pkcs7.messageToPem(p7);
```

<a name="pkcs8" />
### PKCS#8

__Examples__

```js
var pki = forge.pki;

// convert a PEM-formatted private key to a Forge private key
var privateKey = pki.privateKeyFromPem(pem);

// convert a Forge private key to PEM-format
var pem = pki.privateKeyToPem(privateKey);

// convert an ASN.1 PrivateKeyInfo or RSAPrivateKey to a Forge private key
var privateKey = pki.privateKeyFromAsn1(rsaPrivateKey);

// convert a Forge private key to an ASN.1 RSAPrivateKey
var rsaPrivateKey = pki.publicKeyToAsn1(privateKey);

// wrap an RSAPrivateKey ASN.1 object in an ASN.1 PrivateKeyInfo
var privateKeyInfo = pki.wrapRsaPrivateKey(rsaPrivateKey);

// encrypts a PrivateKeyInfo and outputs an EncryptedPrivateKeyInfo
var encryptedPrivateKeyInfo = pki.encryptPrivateKeyInfo(
  privateKeyInfo, 'password', {
    algorithm: 'aes256', // 'aes128', 'aes192', 'aes256', '3des'
  });

// decrypts an ASN.1 EncryptedPrivateKeyInfo
var privateKeyInfo = pki.decryptPrivateKeyInfo(
  encryptedPrivateKeyInfo, 'password');

// converts an EncryptedPrivateKeyInfo to PEM
var pem = pki.encryptedPrivateKeyToPem(encryptedPrivateKeyInfo);

// converts a PEM-encoded EncryptedPrivateKeyInfo to ASN.1 format
var encryptedPrivateKeyInfo = pki.encryptedPrivateKeyFromPem(pem);

// wraps and encrypts a Forge private key and outputs it in PEM format
var pem = pki.encryptRsaPrivateKey(privateKey, 'password');

// encrypts a Forge private key and outputs it in PEM format using OpenSSL's
// proprietary legacy format + encapsulated PEM headers (DEK-Info)
var pem = pki.encryptRsaPrivateKey(privateKey, 'password', {legacy: true});

// decrypts a PEM-formatted, encrypted private key
var privateKey = pki.decryptRsaPrivateKey(pem, 'password');

// sets an RSA public key from a private key
var publicKey = pki.setRsaPublicKey(privateKey.n, privateKey.e);
```

<a name="pkcs10" />
### PKCS#10

Provides certification requests or certificate signing requests (CSR) from
[PKCS#10][].

__Examples__

```js
// generate a key pair
var keys = forge.pki.rsa.generateKeyPair(1024);

// create a certification request (CSR)
var csr = forge.pki.createCertificationRequest();
csr.publicKey = keys.publicKey;
csr.setSubject([{
  name: 'commonName',
  value: 'example.org'
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
}]);
// set (optional) attributes
csr.setAttributes([{
  name: 'challengePassword',
  value: 'password'
}, {
  name: 'unstructuredName',
  value: 'My Company, Inc.'
}]);

// sign certification request
csr.sign(keys.privateKey);

// verify certification request
var verified = csr.verify();

// convert certification request to PEM-format
var pem = forge.pki.certificationRequestToPem(csr);

// convert a Forge certification request from PEM-format
var csr = forge.pki.certificationRequestFromPem(pem);
```

<a name="pkcs12" />
### PKCS#12

Provides the cryptographic archive file format from [PKCS#12][].

__Examples__

```js
// decode p12 from base64
var p12Der = forge.util.decode64(p12b64);
// get p12 as ASN.1 object
var p12Asn1 = forge.asn1.fromDer(p12Der);
// decrypt p12
var p12 = forge.pkcs12.pkcs12FromAsn1(p12Asn1, 'password');
// look at pkcs12.safeContents

// get bags by friendlyName
var bags = pkcs12.getBags({friendlyName: 'test'});

// get bags by localKeyId
var bags = pkcs12.getBags({localKeyId: buffer});

// get bags by localKeyId (input in hex)
var bags = pkcs12.getBags({localKeyIdHex: '7b59377ff142d0be4565e9ac3d396c01401cd879'});

// generate p12, base64 encode
var p12Asn1 = forge.pkcs12.toPkcs12Asn1(
  privateKey, certificateChain, 'password');
var p12Der = forge.asn1.ToDer(p12Asn1).getBytes();
var p12b64 = forge.util.encode64(p12Der);
```

<a name="asn" />
### ASN.1

Provides [ASN.1][] DER encoding and decoding.

__Examples__

```js
var asn1 = forge.asn1;

// create a SubjectPublicKeyInfo
var subjectPublicKeyInfo =
  asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [
    // AlgorithmIdentifier
    asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [
      // algorithm
      asn1.create(asn1.Class.UNIVERSAL, asn1.Type.OID, false,
        asn1.oidToDer(pki.oids['rsaEncryption']).getBytes()),
      // parameters (null)
      asn1.create(asn1.Class.UNIVERSAL, asn1.Type.NULL, false, '')
    ]),
    // subjectPublicKey
    asn1.create(asn1.Class.UNIVERSAL, asn1.Type.BITSTRING, false, [
      // RSAPublicKey
      asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [
        // modulus (n)
        asn1.create(asn1.Class.UNIVERSAL, asn1.Type.INTEGER, false,
          _bnToBytes(key.n)),
        // publicExponent (e)
        asn1.create(asn1.Class.UNIVERSAL, asn1.Type.INTEGER, false,
          _bnToBytes(key.e))
      ])
    ])
  ]);

// serialize an ASN.1 object to DER format
var derBuffer = asn1.toDer(subjectPublicKeyInfo);

// deserialize to an ASN.1 object from a byte buffer filled with DER data
var object = asn1.fromDer(derBuffer);

// convert an OID dot-separated string to a byte buffer
var derOidBuffer = asn1.oidToDer('1.2.840.113549.1.1.5');

// convert a byte buffer with a DER-encoded OID to a dot-separated string
console.log(asn1.derToDer(derOidBuffer));
// output: 1.2.840.113549.1.1.5

// validates that an ASN.1 object matches a particular ASN.1 structure and
// captures data of interest from that structure for easy access
var publicKeyValidator = {
  name: 'SubjectPublicKeyInfo',
  tagClass: asn1.Class.UNIVERSAL,
  type: asn1.Type.SEQUENCE,
  constructed: true,
  captureAsn1: 'subjectPublicKeyInfo',
  value: [{
    name: 'SubjectPublicKeyInfo.AlgorithmIdentifier',
    tagClass: asn1.Class.UNIVERSAL,
    type: asn1.Type.SEQUENCE,
    constructed: true,
    value: [{
      name: 'AlgorithmIdentifier.algorithm',
      tagClass: asn1.Class.UNIVERSAL,
      type: asn1.Type.OID,
      constructed: false,
      capture: 'publicKeyOid'
    }]
  }, {
    // subjectPublicKey
    name: 'SubjectPublicKeyInfo.subjectPublicKey',
    tagClass: asn1.Class.UNIVERSAL,
    type: asn1.Type.BITSTRING,
    constructed: false,
    value: [{
      // RSAPublicKey
      name: 'SubjectPublicKeyInfo.subjectPublicKey.RSAPublicKey',
      tagClass: asn1.Class.UNIVERSAL,
      type: asn1.Type.SEQUENCE,
      constructed: true,
      optional: true,
      captureAsn1: 'rsaPublicKey'
    }]
  }]
};

var capture = {};
var errors = [];
if(!asn1.validate(
  publicKeyValidator, subjectPublicKeyInfo, validator, capture, errors)) {
  throw 'ASN.1 object is not a SubjectPublicKeyInfo.';
}
// capture.subjectPublicKeyInfo contains the full ASN.1 object
// capture.rsaPublicKey contains the full ASN.1 object for the RSA public key
// capture.publicKeyOid only contains the value for the OID
var oid = asn1.derToOid(capture.publicKeyOid);
if(oid !== pki.oids['rsaEncryption']) {
  throw 'Unsupported OID.';
}

// pretty print an ASN.1 object to a string for debugging purposes
asn1.prettyPrint(object);
```

---------------------------------------
## Message Digests

<a name="sha1" />
### SHA1

Provides [SHA-1][] message digests.

__Examples__

```js
var md = forge.md.sha1.create();
md.update('The quick brown fox jumps over the lazy dog');
console.log(md.digest().toHex());
// output: 2fd4e1c67a2d28fced849ee1bb76e7391b93eb12
```

<a name="sha256" />
### SHA256

Provides [SHA-256][] message digests.

__Examples__

```js
var md = forge.md.sha256.create();
md.update('The quick brown fox jumps over the lazy dog');
console.log(md.digest().toHex());
// output: d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592
```

<a name="md5" />
### MD5

Provides [MD5][] message digests.

__Examples__

```js
var md = forge.md.md5.create();
md.update('The quick brown fox jumps over the lazy dog');
console.log(md.digest().toHex());
// output: 9e107d9d372bb6826bd81d3542a419d6
```

<a name="hmac" />
### HMAC

Provides [HMAC][] w/any supported message digest algorithm.

__Examples__

```js
var hmac = forge.hmac.create();
hmac.start('sha1', 'Jefe');
hmac.update('what do ya want for nothing?');
console.log(hmac.digest().toHex());
// output: effcdf6ae5eb2fa2d27416d5f184df9c259a7c79
```

---------------------------------------
## Message Digests

<a name="prng" />
### PRNG

Provides a [Fortuna][]-based cryptographically-secure pseudo-random number
generator, to be used with a cryptographic function backend, ie: [AES][]. An
implementation using [AES][] as a backend is provided. An API for collecting
entropy is given, though if window.crypto.getRandomValues is available, it will
be used automatically.

__Examples__

```js
// get some random bytes synchronously
var bytes = forge.random.getBytesSync(32);
console.log(forge.util.bytesToHex(bytes));

// get some random bytes asynchronously
forge.random.getBytes(32, function(err, bytes) {
  console.log(forge.util.bytesToHex(bytes));
});

// collect some entropy if you'd like
forge.random.collect(someRandomBytes);
jQuery().mousemove(function(e) {
  forge.random.collectInt(e.clientX, 16);
  forge.random.collectInt(e.clientY, 16);
});

// specify a seed file for use with the synchronous API if you'd like
forge.random.seedFileSync = function(needed) {
  // get 'needed' number of random bytes from somewhere
  return fetchedRandomBytes;
};

// specify a seed file for use with the asynchronous API if you'd like
forge.random.seedFile = function(needed, callback) {
  // get the 'needed' number of random bytes from somewhere
  callback(null, fetchedRandomBytes);
});

// register the main thread to send entropy or a Web Worker to receive
// entropy on demand from the main thread
forge.random.registerWorker(self);
```

<a name="task" />
### Tasks

Provides queuing and synchronizing tasks in a web application.

__Examples__

```js
```

<a name="util" />
### Utilities

Provides utility functions, including byte buffer support, base64,
bytes to/from hex, zlib inflate/deflate, etc.

__Examples__

```js
// encode/decode base64
var encoded = forge.util.encode64(str);
var str = forge.util.decode64(decoded);

// encode/decode UTF-8
var encoded = forge.util.encodeUtf8(str);
var str = forge.util.decodeUtf8(decoded);

// bytes to/from hex
var bytes = forge.util.hexToBytes(hex);
var hex = forge.util.bytesToHex(bytes);

// create an empty byte buffer
var buffer = forge.util.createBuffer();
// create a byte buffer from raw binary bytes
var buffer = forge.util.createBuffer(input, 'raw');
// create a byte buffer from utf8 bytes
var buffer = forge.util.createBuffer(input, 'utf8');

// get the length of the buffer in bytes
buffer.length();
// put bytes into the buffer
buffer.putBytes(bytes);
// put a 32-bit integer into the buffer
buffer.putInt32(10);
// buffer to hex
buffer.toHex();
// get a copy of the bytes in the buffer
bytes.bytes(/* count */);
// empty this buffer and get its contents
bytes.getBytes(/* count */);

// convert a forge buffer into a node.js Buffer
// make sure you specify the encoding as 'binary'
var forgeBuffer = forge.util.createBuffer();
var nodeBuffer = new Buffer(forgeBuffer.getBytes(), 'binary');

// convert a node.js Buffer into a forge buffer
// make sure you specify the encoding as 'binary'
var nodeBuffer = new Buffer();
var forgeBuffer = forge.util.createBuffer(nodeBuffer.toString('binary'));

// parse a URL
var parsed = forge.util.parseUrl('http://example.com/foo?bar=baz');
// parsed.scheme, parsed.host, parsed.port, parsed.path, parsed.fullHost
```

<a name="log" />
### Logging

Provides logging to a javascript console using various categories and
levels of verbosity.

__Examples__

```js
```

<a name="debug" />
### Debugging

Provides storage of debugging information normally inaccessible in
closures for viewing/investigation.

__Examples__

```js
```

<a name="fsp" />
### Flash Socket Policy Module

Provides an [Apache][] module "mod_fsp" that can serve up a Flash Socket
Policy. See `mod_fsp/README` for more details. This module makes it easy to
modify an [Apache][] server to allow cross domain requests to be made to it.


Library Details
---------------

* http://digitalbazaar.com/2010/07/20/javascript-tls-1/
* http://digitalbazaar.com/2010/07/20/javascript-tls-2/

Contact
-------

* Code: https://github.com/digitalbazaar/forge
* Bugs: https://github.com/digitalbazaar/forge/issues
* Email: support@digitalbazaar.com

[AES]: http://en.wikipedia.org/wiki/Advanced_Encryption_Standard
[ASN.1]: http://en.wikipedia.org/wiki/ASN.1
[Apache]: http://httpd.apache.org/
[Fortuna]: http://en.wikipedia.org/wiki/Fortuna_(PRNG)
[HMAC]: http://en.wikipedia.org/wiki/HMAC
[JavaScript]: http://en.wikipedia.org/wiki/JavaScript
[MD5]: http://en.wikipedia.org/wiki/MD5
[PKCS#5]: http://en.wikipedia.org/wiki/PKCS
[PKCS#7]: http://en.wikipedia.org/wiki/Cryptographic_Message_Syntax
[PKCS#10]: http://en.wikipedia.org/wiki/Certificate_signing_request
[PKCS#12]: http://en.wikipedia.org/wiki/PKCS_%E2%99%AF12
[SHA-1]: http://en.wikipedia.org/wiki/SHA-1
[SHA-256]: http://en.wikipedia.org/wiki/SHA-256
[TLS]: http://en.wikipedia.org/wiki/Transport_Layer_Security
[X.509]: http://en.wikipedia.org/wiki/X.509
[node.js]: http://nodejs.org/
