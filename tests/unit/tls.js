var ASSERT = require('assert');
var forge = require('../../lib/forge');
require('../../lib/tls');
require('../../lib/aesCipherSuites');
require('../../lib/util');

(function() {
  describe('tls', function() {
    it('should test TLS 1.0 PRF', function() {
      // Note: This test vector is originally from:
      // http://www.imc.org/ietf-tls/mail-archive/msg01589.html
      // But that link is now dead.
      var secret = forge.util.createBuffer().fillWithByte(0xAB, 48).getBytes();
      var seed = forge.util.createBuffer().fillWithByte(0xCD, 64).getBytes();
      var bytes = forge.tls.prf_tls1(secret, 'PRF Testvector', seed, 104);
      var expect =
        'd3d4d1e349b5d515044666d51de32bab258cb521' +
        'b6b053463e354832fd976754443bcf9a296519bc' +
        '289abcbc1187e4ebd31e602353776c408aafb74c' +
        'bc85eff69255f9788faa184cbb957a9819d84a5d' +
        '7eb006eb459d3ae8de9810454b8b2d8f1afbc655' +
        'a8c9a013';
      ASSERT.equal(bytes.toHex(), expect);
    });

    it('should establish a TLS connection and transfer data', function(done) {
      var end = {};
      var data = {};

      createCertificate('server', data);
      createCertificate('client', data);
      data.client.connection = {};
      data.server.connection = {};

      end.client = forge.tls.createConnection({
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
          c.prepare('Hello Server');
        },
        getCertificate: function(c, hint) {
          return data.client.cert;
        },
        getPrivateKey: function(c, cert) {
          return data.client.privateKey;
        },
        tlsDataReady: function(c) {
          end.server.process(c.tlsData.getBytes());
        },
        dataReady: function(c) {
          data.client.connection.data = c.data.getBytes();
          c.close();
        },
        closed: function(c) {
          ASSERT.equal(data.client.connection.commonName, 'server');
          ASSERT.equal(data.client.connection.certVerified, true);
          ASSERT.equal(data.client.connection.data, 'Hello Client');
          done();
        },
        error: function(c, error) {
          ASSERT.equal(error.message, undefined);
        }
      });

      end.server = forge.tls.createConnection({
        server: true,
        caStore: [data.client.cert],
        sessionCache: {},
        cipherSuites: [
          forge.tls.CipherSuites.TLS_RSA_WITH_AES_128_CBC_SHA,
          forge.tls.CipherSuites.TLS_RSA_WITH_AES_256_CBC_SHA],
        connected: function(c) {
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
          end.client.process(c.tlsData.getBytes());
        },
        dataReady: function(c) {
          data.server.connection.data = c.data.getBytes();
          c.prepare('Hello Client');
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

      end.client.handshake();

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
    });

    // see GHSA-hqq3-7jhf-c5jx
    describe('record processing', function() {
      // enough records to exhaust the call stack if each record is handled
      // one call level deeper than the previous one
      var COUNT = 50000;

      // heartbeat_request and heartbeat_response with empty payloads
      var HB_REQUEST = forge.util.hexToBytes('1803010003010000');
      var HB_RESPONSE = forge.util.hexToBytes('1803010003020000');
      // fatal handshake_failure alert
      var ALERT = forge.util.hexToBytes('15030100020228');

      function repeat(bytes, count) {
        var b = forge.util.createBuffer();
        for(var i = 0; i < count; ++i) {
          b.putBytes(bytes);
        }
        return b.getBytes();
      }

      // TLS 1.0 record
      function record(type, fragment) {
        var b = forge.util.createBuffer();
        b.putByte(type);
        b.putByte(3);
        b.putByte(1);
        b.putInt16(fragment.length);
        b.putBytes(fragment);
        return b.getBytes();
      }

      function createConnection(server, log) {
        return forge.tls.createConnection({
          server: server,
          verify: function() {
            return true;
          },
          tlsDataReady: function(c) {
            c.tlsData.getBytes();
          },
          dataReady: function(c) {
            c.data.getBytes();
          },
          heartbeatReceived: function() {
            log.heartbeats++;
            if(log.heartbeats === 1 && log.throwOnFirstHeartbeat) {
              throw new Error('heartbeat callback failed');
            }
          },
          closed: function() {},
          error: function(c, error) {
            log.errors.push(error.message);
          }
        });
      }

      it('should process many heartbeat records as server', function() {
        var log = {heartbeats: 0, errors: []};
        var c = createConnection(true, log);
        var rval = c.process(repeat(HB_RESPONSE, COUNT) + ALERT);
        ASSERT.equal(rval, 0);
        // the alert after all heartbeat records was processed
        ASSERT.deepEqual(log.errors, ['Handshake failure.']);
      });

      it('should process many heartbeat records as client', function() {
        var log = {heartbeats: 0, errors: []};
        var c = createConnection(false, log);
        c.handshake();
        var rval = c.process(repeat(HB_REQUEST, COUNT) + ALERT);
        ASSERT.equal(rval, 0);
        ASSERT.deepEqual(log.errors, ['Handshake failure.']);
      });

      it('should process a message fragmented over many records', function() {
        var log = {heartbeats: 0, errors: []};
        var c = createConnection(true, log);
        // ClientHello header announcing a 16 MiB message, then many 1-byte
        // fragments of it
        var data = record(22, forge.util.hexToBytes('01ffffff')) +
          repeat(record(22, '\x00'), COUNT);
        var rval = c.process(data);
        ASSERT.equal(rval, 0);
        ASSERT.deepEqual(log.errors, []);
        // all records were read
        ASSERT.equal(c.input.length(), 0);
      });

      it('should process many handshake messages per record', function() {
        var log = {heartbeats: 0, errors: []};
        var c = createConnection(false, log);
        c.handshake();
        // ServerHello: TLS 1.0, new session, TLS_RSA_WITH_AES_128_CBC_SHA
        var b = forge.util.createBuffer();
        b.putBytes(forge.util.hexToBytes('0301'));
        b.fillWithByte(0, 32);
        b.putBytes(forge.util.hexToBytes('00002f00'));
        var serverHello = forge.util.hexToBytes('02') +
          forge.util.int32ToBytes(b.length()).substr(1) + b.getBytes();
        // records full of 4-byte HelloRequest messages
        var helloRequests = repeat(
          record(22, repeat(forge.util.hexToBytes('00000000'), 4096)),
          Math.ceil(COUNT / 4096));
        var rval = c.process(record(22, serverHello) + helloRequests + ALERT);
        ASSERT.equal(rval, 0);
        ASSERT.deepEqual(log.errors, ['Handshake failure.']);
      });

      it('should process records split across calls', function() {
        var log = {heartbeats: 0, errors: []};
        var c = createConnection(true, log);
        var data = repeat(HB_RESPONSE, 3) + ALERT;
        var rvals = [];
        for(var i = 0; i < data.length; ++i) {
          rvals.push(c.process(data.charAt(i)));
        }
        // bytes needed for the next header or fragment, 0 when complete
        ASSERT.deepEqual(rvals.slice(0, 8), [4, 3, 2, 1, 3, 2, 1, 0]);
        ASSERT.deepEqual(log.errors, ['Handshake failure.']);
      });

      it('should continue processing after a callback throws', function() {
        var log = {heartbeats: 0, errors: [], throwOnFirstHeartbeat: true};
        var c = createConnection(false, log);
        c.prepareHeartbeatRequest('');
        ASSERT.throws(function() {
          c.process(repeat(HB_RESPONSE, 2) + ALERT);
        }, /heartbeat callback failed/);
        ASSERT.equal(log.heartbeats, 1);
        ASSERT.deepEqual(log.errors, []);
        // the remaining buffered records are still processed
        ASSERT.equal(c.process(), 0);
        ASSERT.equal(log.heartbeats, 2);
        ASSERT.deepEqual(log.errors, ['Handshake failure.']);
      });
    });

    // see GHSA-8hrf-8g6f-7xwp
    describe('fragmented handshake messages', function() {
      // TLS 1.0 record
      function record(type, fragment) {
        var b = forge.util.createBuffer();
        b.putByte(type);
        b.putByte(3);
        b.putByte(1);
        b.putInt16(fragment.length);
        b.putBytes(fragment);
        return b.getBytes();
      }

      function createConnection(server, log) {
        var c = forge.tls.createConnection({
          server: server,
          verify: function() {
            return true;
          },
          tlsDataReady: function(c) {
            log.sent += c.tlsData.getBytes();
          },
          dataReady: function(c) {
            c.data.getBytes();
          },
          closed: function() {},
          error: function(c, error) {
            log.errors.push(error.message);
          }
        });
        if(!server) {
          c.handshake();
          // drop the ClientHello
          log.sent = '';
        }
        return c;
      }

      // start of a handshake message (ClientHello or ServerHello) announcing
      // more bytes than the record holds
      function firstFragment(server) {
        return record(22, forge.util.hexToBytes(
          (server ? '01' : '02') + '000010' + '0301'));
      }

      var interleaved = {
        change_cipher_spec: record(20, '\x01'),
        alert: record(21, forge.util.hexToBytes('0228')),
        application_data: record(23, 'data'),
        heartbeat: record(24, forge.util.hexToBytes('010000'))
      };

      [true, false].forEach(function(server) {
        var mode = server ? 'server' : 'client';
        Object.keys(interleaved).forEach(function(name) {
          it('should fail on ' + name + ' in a fragmented message (' + mode +
            ')', function() {
            var log = {sent: '', errors: []};
            var c = createConnection(server, log);
            ASSERT.doesNotThrow(function() {
              c.process(firstFragment(server) + interleaved[name]);
            });
            ASSERT.deepEqual(log.errors, ['Invalid fragmented record.']);
            ASSERT.equal(c.fail, true);
            // fatal unexpected_message alert
            var alert = forge.util.createBuffer(log.sent);
            ASSERT.equal(alert.getByte(), 21);
            alert.getBytes(4);
            ASSERT.equal(alert.bytes(), forge.util.hexToBytes('020a'));
            // further input is ignored
            ASSERT.equal(c.process(interleaved[name]), 0);
            ASSERT.deepEqual(log.errors, ['Invalid fragmented record.']);
          });
        });

        it('should accept continuation records (' + mode + ')', function() {
          var log = {sent: '', errors: []};
          var c = createConnection(server, log);
          var rval = c.process(firstFragment(server) + record(22, '\x00'));
          ASSERT.equal(rval, 0);
          ASSERT.deepEqual(log.errors, []);
          ASSERT.equal(c.fail, false);
          ASSERT.equal(log.sent, '');
        });
      });
    });
  });
})();
