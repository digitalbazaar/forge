(function() {

function Tests(ASSERT, PKI, MD, UTIL) {
  var _pem = {
    privateKey: '-----BEGIN RSA PRIVATE KEY-----\r\n' +
      'MIICXQIBAAKBgQDL0EugUiNGMWscLAVM0VoMdhDZEJOqdsUMpx9U0YZI7szokJqQ\r\n' +
      'NIwokiQ6EonNnWSMlIvy46AhnlRYn+ezeTeU7eMGTkP3VF29vXBo+dLq5e+8VyAy\r\n' +
      'Q3FzM1wI4ts4hRACF8w6mqygXQ7i/SDu8/rXqRGtvnM+z0MYDdKo80efzwIDAQAB\r\n' +
      'AoGAIzkGONi5G+JifmXlLJdplom486p3upf4Ce2/7mqfaG9MnkyPSairKD/JXvfh\r\n' +
      'NNWkkN8DKKDKBcVVElPgORYT0qwrWc7ueLBMUCbRXb1ZyfEulimG0R3kjUh7NYau\r\n' +
      'DaIkVgfykXGSQMZx8FoaT6L080zd+0emKDDYRrb+/kgJNJECQQDoUZoiC2K/DWNY\r\n' +
      'h3/ppZ0ane2y4SBmJUHJVMPQ2CEgxsrJTxet668ckNCKaOP/3VFPoWC41f17DvKq\r\n' +
      'noYINNntAkEA4JbZBZBVUrQFhHlrpXT4jzqtO2RlKZzEq8qmFZfEErxOT1WMyyCi\r\n' +
      'lAQ5gUKardo1Kf0omC8Xq/uO9ZYdED55KwJBALs6cJ65UFaq4oLJiQPzLd7yokuE\r\n' +
      'dcj8g71PLBTW6jPxIiMFNA89nz3FU9wIVp+xbMNhSoMMKqIPVPC+m0Rn260CQQDA\r\n' +
      'I83fWK/mZWUjBM33a68KumRiH238v8XyQxj7+C8i6D8G2GXvkigFAehAkb7LZZd+\r\n' +
      'KLuGFyPlWv3fVWHf99KpAkBQFKk3MRMl6IGJZUEFQe4l5whm8LkGU4acSqv9B3xt\r\n' +
      'qROkCrsFrMPqjuuzEmyHoQZ64r2PLJg7FOuyhBnQUOt4\r\n' +
      '-----END RSA PRIVATE KEY-----\r\n',
    publicKey: '-----BEGIN PUBLIC KEY-----\r\n' +
      'MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDL0EugUiNGMWscLAVM0VoMdhDZ\r\n' +
      'EJOqdsUMpx9U0YZI7szokJqQNIwokiQ6EonNnWSMlIvy46AhnlRYn+ezeTeU7eMG\r\n' +
      'TkP3VF29vXBo+dLq5e+8VyAyQ3FzM1wI4ts4hRACF8w6mqygXQ7i/SDu8/rXqRGt\r\n' +
      'vnM+z0MYDdKo80efzwIDAQAB\r\n' +
      '-----END PUBLIC KEY-----\r\n',
    certificate: '-----BEGIN CERTIFICATE-----\r\n' +
      'MIIDIjCCAougAwIBAgIJANE2aHSbwpaRMA0GCSqGSIb3DQEBBQUAMGoxCzAJBgNV\r\n' +
      'BAYTAlVTMREwDwYDVQQIEwhWaXJnaW5pYTETMBEGA1UEBxMKQmxhY2tzYnVyZzEN\r\n' +
      'MAsGA1UEChMEVGVzdDENMAsGA1UECxMEVGVzdDEVMBMGA1UEAxMMbXlzZXJ2ZXIu\r\n' +
      'Y29tMB4XDTEwMDYxOTE3MzYyOFoXDTExMDYxOTE3MzYyOFowajELMAkGA1UEBhMC\r\n' +
      'VVMxETAPBgNVBAgTCFZpcmdpbmlhMRMwEQYDVQQHEwpCbGFja3NidXJnMQ0wCwYD\r\n' +
      'VQQKEwRUZXN0MQ0wCwYDVQQLEwRUZXN0MRUwEwYDVQQDEwxteXNlcnZlci5jb20w\r\n' +
      'gZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBAMvQS6BSI0YxaxwsBUzRWgx2ENkQ\r\n' +
      'k6p2xQynH1TRhkjuzOiQmpA0jCiSJDoSic2dZIyUi/LjoCGeVFif57N5N5Tt4wZO\r\n' +
      'Q/dUXb29cGj50url77xXIDJDcXMzXAji2ziFEAIXzDqarKBdDuL9IO7z+tepEa2+\r\n' +
      'cz7PQxgN0qjzR5/PAgMBAAGjgc8wgcwwHQYDVR0OBBYEFPV1Y+DHXW6bA/r9sv1y\r\n' +
      'NJ8jAwMAMIGcBgNVHSMEgZQwgZGAFPV1Y+DHXW6bA/r9sv1yNJ8jAwMAoW6kbDBq\r\n' +
      'MQswCQYDVQQGEwJVUzERMA8GA1UECBMIVmlyZ2luaWExEzARBgNVBAcTCkJsYWNr\r\n' +
      'c2J1cmcxDTALBgNVBAoTBFRlc3QxDTALBgNVBAsTBFRlc3QxFTATBgNVBAMTDG15\r\n' +
      'c2VydmVyLmNvbYIJANE2aHSbwpaRMAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQEF\r\n' +
      'BQADgYEARdH2KOlJWTC1CS2y/PAvg4uiM31PXMC1hqSdJlnLM1MY4hRfuf9VyTeX\r\n' +
      'Y6FdybcyDLSxKn9id+g9229ci9/s9PI+QmD5vXd8yZyScLc2JkYB4GC6+9D1+/+x\r\n' +
      's2hzMxuK6kzZlP+0l9LGcraMQPGRydjCARZZm4Uegln9rh85XFQ=\r\n' +
      '-----END CERTIFICATE-----\r\n'
  };

  describe('x509', function() {
    it('should convert certificate to/from PEM', function() {
      var certificate = PKI.certificateFromPem(_pem.certificate);
      ASSERT.equal(PKI.certificateToPem(certificate), _pem.certificate);
    });

    it('should verify self-signed certificate', function() {
      var certificate = PKI.certificateFromPem(_pem.certificate);
      ASSERT.ok(certificate.verify(certificate));
    });

    it('should generate a self-signed certificate', function() {
      var keys = {
        privateKey: PKI.privateKeyFromPem(_pem.privateKey),
        publicKey: PKI.publicKeyFromPem(_pem.publicKey)
      };
      var cert = PKI.createCertificate();
      cert.publicKey = keys.publicKey;
      cert.serialNumber = '01';
      cert.validity.notBefore = new Date();
      cert.validity.notAfter = new Date();
      cert.validity.notAfter.setFullYear(
        cert.validity.notBefore.getFullYear() + 1);
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
        }]
      }, {
        name: 'subjectKeyIdentifier'
      }]);
      // FIXME: add authorityKeyIdentifier extension

      cert.sign(keys.privateKey);

      var pem = PKI.certificateToPem(cert);
      cert = PKI.certificateFromPem(pem);

      // verify certificate
      var caStore = PKI.createCaStore();
      caStore.addCertificate(cert);
      PKI.verifyCertificateChain(caStore, [cert], function(vfd, depth, chain) {
        ASSERT.equal(vfd, true);
        ASSERT.ok(cert.verifySubjectKeyIdentifier());
        return true;
      });
    });
  });
}

// check for AMD
if(typeof define === 'function') {
  define([
    'forge/pki',
    'forge/md',
    'forge/util'
  ], function(PKI, MD, UTIL) {
    Tests(
      // Global provided by test harness
      ASSERT,
      PKI(),
      MD(),
      UTIL()
    );
  });
}
// assume NodeJS
else if(typeof module === 'object' && module.exports) {
  Tests(
    require('assert'),
    require('../../js/pki')(),
    require('../../js/md')(),
    require('../../js/util')());
}

})();
