(function() {

function Tests(ASSERT, forge) {
  var ByteBuffer = forge.util.ByteBuffer;

  describe('tls', function() {
    var clientSessionCache = forge.tls.createSessionCache();
    var serverSessionCache = forge.tls.createSessionCache();

    function createCertificate(cn, data) {
      var keys = forge.pki.rsa.generateKeyPair(512);
      var cert = forge.pki.createCertificate();
      cert.publicKey = keys.publicKey;
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
          value: 'https://myuri.com/webid#me'
        }]
      }]);
      cert.sign(keys.privateKey);
      data[cn] = {
        cert: forge.pki.certificateToPem(cert),
        privateKey: forge.pki.privateKeyToPem(keys.privateKey)
      };
    }

    function createClientConnection(options, callback) {
      var version = options.version || forge.tls.Version;
      var end = options.end;
      var data = options.data;
      var assert = options.assert || {};
      return forge.tls.createConnection({
        version: version,
        server: false,
        caStore: [data.server.cert],
        sessionCache: {},
        cipherSuites: [
          forge.tls.CipherSuites.TLS_RSA_WITH_AES_128_CBC_SHA,
          forge.tls.CipherSuites.TLS_RSA_WITH_AES_256_CBC_SHA],
        virtualHost: 'server',
        verify: function(c, verified, depth, certs) {
          data.client.connection.commonName =
            certs[0].subject.getField('CN').value;
          data.client.connection.certVerified = verified;
          return true;
        },
        connected: function(c) {
          if(assert.version) {
            ASSERT.equal(c.version.major, assert.version.major);
            ASSERT.equal(c.version.minor, assert.version.minor);
          }
          c.prepare(new ByteBuffer('Hello Server', 'utf8'));
        },
        getCertificate: function(c, hint) {
          return data.client.cert;
        },
        getPrivateKey: function(c, cert) {
          return data.client.privateKey;
        },
        tlsDataReady: function(c) {
          end.server.process(c.tlsData);
        },
        dataReady: function(c) {
          data.client.connection.data = c.data.getBytes();
          c.close();
        },
        closed: function(c) {
          ASSERT.equal(data.client.connection.commonName, 'server');
          ASSERT.equal(data.client.connection.certVerified, true);
          ASSERT.equal(data.client.connection.data, 'Hello Client');
          callback();
        },
        error: function(c, error) {
          ASSERT.equal(error.message, undefined);
        }
      });
    }

    function createServerConnection(options) {
      var version = options.version || forge.tls.Version;
      var end = options.end;
      var data = options.data;
      var assert = options.assert || {};
      return forge.tls.createConnection({
        version: version,
        server: true,
        caStore: [data.client.cert],
        sessionCache: {},
        cipherSuites: [
          forge.tls.CipherSuites.TLS_RSA_WITH_AES_128_CBC_SHA,
          forge.tls.CipherSuites.TLS_RSA_WITH_AES_256_CBC_SHA],
        connected: function(c) {
          if(assert.version) {
            ASSERT.equal(c.version.major, assert.version.major);
            ASSERT.equal(c.version.minor, assert.version.minor);
          }
        },
        verifyClient: true,
        verify: function(c, verified, depth, certs) {
          data.server.connection.commonName =
            certs[0].subject.getField('CN').value;
          data.server.connection.certVerified = verified;
          return true;
        },
        getCertificate: function(c, hint) {
          data.server.connection.certHint = hint[0];
          return data.server.cert;
        },
        getPrivateKey: function(c, cert) {
          return data.server.privateKey;
        },
        tlsDataReady: function(c) {
          end.client.process(c.tlsData);
        },
        dataReady: function(c) {
          data.server.connection.data = c.data.getBytes();
          c.prepare(new ByteBuffer('Hello Client', 'utf8'));
          c.close();
        },
        closed: function(c) {
          ASSERT.equal(data.server.connection.certHint, 'server');
          ASSERT.equal(data.server.connection.commonName, 'client');
          ASSERT.equal(data.server.connection.certVerified, true);
          ASSERT.equal(data.server.connection.data, 'Hello Server');
        },
        error: function(c, error) {
          ASSERT.equal(error.message, undefined);
        }
      });
    }

    it('should test TLS 1.0 PRF', function() {
      // Note: This test vector is originally from:
      // http://www.imc.org/ietf-tls/mail-archive/msg01589.html
      // But that link is now dead.
      var secret = new forge.util.ByteBuffer().fillWithByte(0xAB, 48);
      var seed = new forge.util.ByteBuffer().fillWithByte(0xCD, 64);
      var bytes = forge.tls.prf_tls1(secret, 'PRF Testvector',  seed, 104);
      var expect =
        'd3d4d1e349b5d515044666d51de32bab258cb521' +
        'b6b053463e354832fd976754443bcf9a296519bc' +
        '289abcbc1187e4ebd31e602353776c408aafb74c' +
        'bc85eff69255f9788faa184cbb957a9819d84a5d' +
        '7eb006eb459d3ae8de9810454b8b2d8f1afbc655' +
        'a8c9a013';
      ASSERT.equal(bytes.toString('hex'), expect);
    });

    it('should establish a TLS 1.0 connection and transfer data', function(done) {
      var end = {};
      var data = {};

      createCertificate('server', data);
      createCertificate('client', data);
      data.client.connection = {};
      data.server.connection = {};

      var assert = {
        version: {major: 3, minor: 1}
      };
      end.client = createClientConnection({
        version: forge.tls.Versions.TLS_1_0,
        end: end,
        data: data,
        assert: assert
      }, done);
      end.server = createServerConnection({
        end: end,
        data: data,
        assert: assert
      });

      end.client.handshake();
    });

    it('should establish a TLS 1.1 connection and transfer data', function(done) {
      var end = {};
      var data = {};

      createCertificate('server', data);
      createCertificate('client', data);
      data.client.connection = {};
      data.server.connection = {};

      var assert = {
        version: {major: 3, minor: 2}
      };
      end.client = createClientConnection({
        version: forge.tls.Versions.TLS_1_1,
        end: end,
        data: data,
        assert: assert
      }, done);
      end.server = createServerConnection({
        end: end,
        data: data,
        assert: assert
      });

      end.client.handshake();
    });

    it('should test TLS 1.2 PRF', function() {
      // Note: This test vector is originally from:
      // https://www.ietf.org/mail-archive/web/tls/current/msg03416.html
      var secret = new forge.util.ByteBuffer('9bbe436ba940f017b17652849a71db35', 'hex');
      var seed = new forge.util.ByteBuffer('a0ba9f936cda311827a6f796ffd5198c', 'hex');
      var bytes = forge.tls.prf_sha256(secret, 'test label', seed, 100);
      var expect =
        'e3f229ba727be17b8d122620557cd453c2aab21d07c3d495329b52d4e61edb5a' +
        '6b301791e90d35c9c9a46b4e14baf9af0fa022f7077def17abfd3797c0564bab' +
        '4fbc91666e9def9b97fce34f796789baa48082d122ee42c5a72e5a5110fff701' +
        '87347b66';
      ASSERT.equal(bytes.toString('hex'), expect);
    });

    // TODO: add session resumption test
  });
}

// check for AMD
if(typeof define === 'function') {
  define([
    'forge/forge'
  ], function(forge) {
    Tests(
      // Global provided by test harness
      ASSERT,
      forge
    );
  });
} else if(typeof module === 'object' && module.exports) {
  // assume NodeJS
  Tests(
    require('assert'),
    require('../../js/forge'));
}

})();
