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
      var bytes = forge.tls.prf_tls_1_0(secret, 'PRF Testvector',  seed, 104);
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
      var hashesToTest = ['sha256', 'sha384', 'sha512'];
      var secretsToTest = [
        '9bbe436ba940f017b17652849a71db35',
        'b80b733d6ceefcdc71566ea48e5567df',
        'b0323523c1853599584d88568bbb05eb'];
      var seedsToTest = [
        'a0ba9f936cda311827a6f796ffd5198c',
        'cd665cf6a8447dd6ff8b27555edb7465',
        'd4640e12e4bcdbfb437f03e6ae418ee5'];
      var byteLengthsToTest = [100, 148, 196];
      var expectedOutputs = [
        'e3f229ba727be17b8d122620557cd453c2aab21d07c3d495329b52d4e61edb5a' +
        '6b301791e90d35c9c9a46b4e14baf9af0fa022f7077def17abfd3797c0564bab' +
        '4fbc91666e9def9b97fce34f796789baa48082d122ee42c5a72e5a5110fff701' +
          '87347b66',
        '7b0c18e9ced410ed1804f2cfa34a336a1c14dffb4900bb5fd7942107e81c83cd' +
        'e9ca0faa60be9fe34f82b1233c9146a0e534cb400fed2700884f9dc236f80edd' +
        '8bfa961144c9e8d792eca722a7b32fc3d416d473ebc2c5fd4abfdad05d918425' +
        '9b5bf8cd4d90fa0d31e2dec479e4f1a26066f2eea9a69236a3e52655c9e9aee6' +
          '91c8f3a26854308d5eaa3be85e0990703d73e56f',
        '1261f588c798c5c201ff036e7a9cb5edcd7fe3f94c669a122a4638d7d508b283' +
        '042df6789875c7147e906d868bc75c45e20eb40c1cf4a1713b27371f68432592' +
        'f7dc8ea8ef223e12ea8507841311bf68653d0cfc4056d811f025c45ddfa6e6fe' +
        'c702f054b409d6f28dd0a3233e498da41a3e75c5630eedbe22fe254e33a1b0e9' +
        'f6b9826675bec7d01a845658dc9c397545401d40b9f46c7a400ee1b8f81ca0a6' +
        '0d1a397a1028bff5d2ef5066126842fb8da4197632bdb54ff6633f86bbc836e6' +
          '40d4d898'];
      for(var i = 0; i < hashesToTest.length; ++i) {
        var hashAlgorithm = hashesToTest[i];
        var secret = new forge.util.ByteBuffer(secretsToTest[i], 'hex');
        var seed = new forge.util.ByteBuffer(seedsToTest[i], 'hex');
        var byteLength = byteLengthsToTest[i];
        var bytes = forge.tls.prf_tls_1_2(
          hashAlgorithm, secret, 'test label', seed, byteLength);
        ASSERT.equal(bytes.toString('hex'), expectedOutputs[i]);
      }
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
