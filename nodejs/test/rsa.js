
((function() {

    function Tests(ASSERT, PKI, RSA) {

		describe('pki', function() {

		    it('generate 128 bit key pair', function() {

				var pair = RSA.generateKeyPair(128);

				ASSERT.equal(PKI.privateKeyToPem(pair.privateKey).indexOf('-----BEGIN RSA PRIVATE KEY-----'), 0);
				ASSERT.equal(PKI.publicKeyToPem(pair.publicKey).indexOf('-----BEGIN PUBLIC KEY-----'), 0);
		    });

		});

    }

    // Check for AMD
    if (typeof define === 'function') {
        define([
        	'forge/pki',
        	'forge/rsa'
        ], function(PKI, RSA) {
            Tests(
            	// Global provided by test harness
            	ASSERT,
            	PKI,
            	RSA
            );
        });
    } else
    // Assume NodeJS
    if (typeof exports === 'object') {
        Tests(
        	require('assert'),
        	require('../../js/pki'),
        	require('../../js/rsa')
        );
    }

})());
