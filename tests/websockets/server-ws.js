// Forge WebSockets Test Server
var forge = require('../..');
var ws = require('nodejs-websocket');

// function to create certificate
var createCert = function(cn, data) {
  console.log(
    'Generating 512-bit key-pair and certificate for \"' + cn + '\".');
  var keys = forge.pki.rsa.generateKeyPair(512);
  console.log('key-pair created.');

  var cert = forge.pki.createCertificate();
  cert.serialNumber = '01';
  cert.validity.notBefore = new Date();
  cert.validity.notAfter = new Date();
  cert.validity.notAfter.setFullYear(
    cert.validity.notBefore.getFullYear() + 1);
  var attrs = [{
    name: 'commonName',
    value: cn
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
      value: 'http://myuri.com/webid#me'
    }]
  }]);
  // FIXME: add subjectKeyIdentifier extension
  // FIXME: add authorityKeyIdentifier extension
  cert.publicKey = keys.publicKey;

  // self-sign certificate
  cert.sign(keys.privateKey);

  // save data
  data[cn] = {
    cert: forge.pki.certificateToPem(cert),
    privateKey: forge.pki.privateKeyToPem(keys.privateKey)
  };

  console.log('certificate created for \"' + cn + '\": \n' + data[cn].cert);
};

var data = {};

// create certificate for server
createCert('server', data);

// function to create TLS server connection
var createTls = function(websocket) {
  return forge.tls.createConnection({
    server: true,
    caStore: [],
    sessionCache: {},
    // supported cipher suites in order of preference
    cipherSuites: [
      forge.tls.CipherSuites.TLS_RSA_WITH_AES_128_CBC_SHA,
      forge.tls.CipherSuites.TLS_RSA_WITH_AES_256_CBC_SHA],
    connected: function(c) {
      console.log('Server connected');
    },
    verifyClient: true,
    verify: function(c, verified, depth, certs) {
      console.log(
        'Server verifying certificate w/CN: \"' +
          certs[0].subject.getField('CN').value +
          '\", verified: ' + verified + '...');

      // accept any certificate (could actually do WebID authorization from
      // here within the protocol)
      return true;
    },
    getCertificate: function(c, hint) {
      console.log('Server getting certificate for \"' + hint[0] + '\"...');
      return data.server.cert;
    },
    getPrivateKey: function(c, cert) {
      return data.server.privateKey;
    },
    tlsDataReady: function(c) {
      // send base64-encoded TLS data over websocket
      websocket.send(forge.util.encode64(c.tlsData.getBytes()));
    },
    dataReady: function(c) {
      console.log('Server received \"' + c.data.getBytes() + '\"');

      // send response
      c.prepare('Hello Client');
    },
    closed: function(c) {
      console.log('Server disconnected.');
      websocket.close();
    },
    error: function(c, error) {
      console.log('Server error: ' + error.message);
    }
  });
};

// create websocket server
let port = 8080;
let wsServer = ws
  .createServer({port: port/*, secure: true*/}, function(websocket) {
    console.log('[ws-server] connection:', websocket.socket.address());

    // create TLS server connection
    let tls = createTls(websocket);

    // close connection after 10 seconds
    let toId = setTimeout(websocket.close, 10 * 1000);

    websocket.on('text', function(data) {
      //console.log('[ws-server] data:', data);
      // base64-decode data and process it
      tls.process(forge.util.decode64(data));
    });

    websocket.on('close', function() {
      clearTimeout(toId);
      console.log('[ws-server]: closed');
    });

    websocket.on('error', function(err) {
      console.error('[ws-server]: error:', err);
    });
  });
wsServer.listen(port, () => {
  console.log('[ws-server] listening:', wsServer.socket.address());
});

