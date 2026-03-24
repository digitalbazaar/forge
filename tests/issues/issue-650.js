var ASSERT = require('assert');
var ASN1 = require('../../lib/asn1');
var PKI = require('../../lib/pki');
var PEM = require('../../lib/pem');
var PKCS12 = require('../../lib/pkcs12');
var UTIL = require('../../lib/util');

/*
encoding a certificate with PSS signature with missing NULL parameters
in digest algorithm identifiers results in modified certificate

reencoding should generally not result in a changed signature AlgorithmIdentifier
 */

(function() {
    var originalX509 = '-----BEGIN CERTIFICATE-----\r\n' +
    'MIIB6DCCASagAwIBAgIBATA4BgkqhkiG9w0BAQowK6ANMAsGCWCGSAFlAwQCAaEa\r\n' +
    'MBgGCSqGSIb3DQEBCDALBglghkgBZQMEAgEwDzENMAsGA1UEAwwEdGVzdDAeFw0x\r\n' +
    'OTAyMDgxMzM5MjZaFw0xOTAzMTAxMzM5MjZaMA8xDTALBgNVBAMMBHRlc3QwgZ8w\r\n' +
    'DQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBAMSu5oSrd1yqH6HbPjACXXZuvC08juyI\r\n' +
    'rXXF4nHGcUc52O99frFkhwv+uUtk4P0L8/XlFwUrB1Admmi0NF8mfW7yAWIr/x2O\r\n' +
    'iKWdpBK5VTSRNm8ZDYI13g37C3T7nVCUjET+QGzf13n5GE13oiFi80hsyBJ8zJpd\r\n' +
    'AipqfWBOy7s/AgMBAAEwOAYJKoZIhvcNAQEKMCugDTALBglghkgBZQMEAgGhGjAY\r\n' +
    'BgkqhkiG9w0BAQgwCwYJYIZIAWUDBAIBA4GBADUl7l6icPVq0RAZZ9brxVHxj9Yr\r\n' +
    'lfdLOPCFpOzQLbi1jUDPr0387QEhSsfc1nsTzgOe9SlSk2BjH8yCUrAeD5F6Pn+W\r\n' +
    '/BlUbNonVER3XAsxov0VvPHKyvV3vpEFQq63mcDUjWNnv0bLRUqxnDY5Az5BqBvC\r\n' +
    'oDeYFEKdUe2ZlOug\r\n' +
    '-----END CERTIFICATE-----\r\n';

    var base64EncodedPkcs12 = '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' +
    'AW0AZT/UAgMBhqA=';
    var p12Passphrase = 'test';

    describe('#650', function() {
        it('should reencode the certificate with binary identical result', function() {
            var expected = ASN1.prettyPrint(ASN1.fromDer(PEM.decode(originalX509)[0].body));

            var parsed = PKI.certificateFromPem(originalX509);
            var reencoded = PKI.certificateToPem(parsed);

            var actual = ASN1.prettyPrint(ASN1.fromDer(PEM.decode(reencoded)[0].body));

            ASSERT.strictEqual(expected, actual, 'reencoding the certificate lead to ASN1 changes');
        });

        it('should decode the certificate in the original form from the PKCS#12', function() {
            var expected = ASN1.prettyPrint(ASN1.fromDer(PKI.pemToDer(originalX509)));

            var p12 = PKCS12.pkcs12FromAsn1(
                ASN1.fromDer(UTIL.decode64(base64EncodedPkcs12)),
                p12Passphrase
            );

            var certBags = p12.getBags({bagType: PKI.oids.certBag})[PKI.oids.certBag];
            var cert = certBags[0].cert;

            var actual = ASN1.prettyPrint(ASN1.fromDer(PKI.pemToDer(PKI.certificateToPem(cert))));

            ASSERT.strictEqual(expected, actual, 'extracting the certificate from PKCS#12 lead to ASN1 changes');
        });
    });
})();
