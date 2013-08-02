(function() {

function Tests(ASSERT, PKI) {
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
      '-----END PUBLIC KEY-----\r\n'
  };

  describe('csr', function() {
    it('should generate a certification request', function() {
      var keys = {
        privateKey: PKI.privateKeyFromPem(_pem.privateKey),
        publicKey: PKI.publicKeyFromPem(_pem.publicKey)
      };
      var csr = PKI.createCertificationRequest();
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
      // add optional attributes
      csr.setAttributes([{
        name: 'challengePassword',
        value: 'password'
      }, {
        name: 'unstructuredName',
        value: 'My company'
      }]);

      // sign certification request
      csr.sign(keys.privateKey);

      var pem = PKI.certificationRequestToPem(csr);
      csr = PKI.certificationRequestFromPem(pem);
      ASSERT.ok(csr.verify());
    });
  });
}

// check for AMD
if(typeof define === 'function') {
  define([
    'forge/pki'
  ], function(PKI) {
    Tests(
      // Global provided by test harness
      ASSERT,
      PKI()
    );
  });
}
// assume NodeJS
else if(typeof module === 'object' && module.exports) {
  Tests(
    require('assert'),
    require('../../js/pki')());
}

})();
