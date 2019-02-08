var ASSERT = require('assert');
var ASN1 = require('../../lib/asn1');
var PKI = require('../../lib/pki');
var PEM = require('../../lib/pem');

/*
encoding a certificate with PSS signature with missing NULL parameters
in digest algorithm identifiers results in modified certificate


 */

(function() {
    var original = '-----BEGIN CERTIFICATE-----\r\n' +
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

    describe('#650', function() {
        it('should reencode the certificate with binary identical result', function() {
            var expected = ASN1.prettyPrint(ASN1.fromDer(PEM.decode(original)[0].body));

            var parsed = PKI.certificateFromPem(original);
            var reencoded = PKI.certificateToPem(parsed);

            var actual = ASN1.prettyPrint(ASN1.fromDer(PEM.decode(reencoded)[0].body));
        
            ASSERT.strictEqual(expected, actual, 'reencoding the certificate lead to ASN1 changes')
        })
    })
})()