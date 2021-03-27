var ASSERT = require('assert');
var PEM = require('../../lib/pem');

(function() {
  var _input = '-----BEGIN PRIVACY-ENHANCED MESSAGE-----\r\n' +
    'Proc-Type: 4,ENCRYPTED\r\n' +
    'Content-Domain: RFC822\r\n' +
    'DEK-Info: DES-CBC,F8143EDE5960C597\r\n' +
    'Originator-ID-Symmetric: linn@zendia.enet.dec.com,,\r\n' +
    'Recipient-ID-Symmetric: linn@zendia.enet.dec.com,ptf-kmc,3\r\n' +
    'Key-Info: DES-ECB,RSA-MD2,9FD3AAD2F2691B9A,\r\n' +
    ' B70665BB9BF7CBCDA60195DB94F727D3\r\n' +
    'Recipient-ID-Symmetric: pem-dev@tis.com,ptf-kmc,4\r\n' +
    'Key-Info: DES-ECB,RSA-MD2,161A3F75DC82EF26,\r\n' +
    ' E2EF532C65CBCFF79F83A2658132DB47\r\n' +
    '\r\n' +
    'LLrHB0eJzyhP+/fSStdW8okeEnv47jxe7SJ/iN72ohNcUk2jHEUSoH1nvNSIWL9M\r\n' +
    '8tEjmF/zxB+bATMtPjCUWbz8Lr9wloXIkjHUlBLpvXR0UrUzYbkNpk0agV2IzUpk\r\n' +
    'J6UiRRGcDSvzrsoK+oNvqu6z7Xs5Xfz5rDqUcMlK1Z6720dcBWGGsDLpTpSCnpot\r\n' +
    'dXd/H5LMDWnonNvPCwQUHg==\r\n' +
    '-----END PRIVACY-ENHANCED MESSAGE-----\r\n' +
    '-----BEGIN PRIVACY-ENHANCED MESSAGE-----\r\n' +
    'Proc-Type: 4,ENCRYPTED\r\n' +
    'Content-Domain: RFC822\r\n' +
    'DEK-Info: DES-CBC,BFF968AA74691AC1\r\n' +
    'Originator-Certificate:\r\n' +
    ' MIIBlTCCAScCAWUwDQYJKoZIhvcNAQECBQAwUTELMAkGA1UEBhMCVVMxIDAeBgNV\r\n' +
    ' BAoTF1JTQSBEYXRhIFNlY3VyaXR5LCBJbmMuMQ8wDQYDVQQLEwZCZXRhIDExDzAN\r\n' +
    ' BgNVBAsTBk5PVEFSWTAeFw05MTA5MDQxODM4MTdaFw05MzA5MDMxODM4MTZaMEUx\r\n' +
    ' CzAJBgNVBAYTAlVTMSAwHgYDVQQKExdSU0EgRGF0YSBTZWN1cml0eSwgSW5jLjEU\r\n' +
    ' MBIGA1UEAxMLVGVzdCBVc2VyIDEwWTAKBgRVCAEBAgICAANLADBIAkEAwHZHl7i+\r\n' +
    ' yJcqDtjJCowzTdBJrdAiLAnSC+CnnjOJELyuQiBgkGrgIh3j8/x0fM+YrsyF1u3F\r\n' +
    ' LZPVtzlndhYFJQIDAQABMA0GCSqGSIb3DQEBAgUAA1kACKr0PqphJYw1j+YPtcIq\r\n' +
    ' iWlFPuN5jJ79Khfg7ASFxskYkEMjRNZV/HZDZQEhtVaU7Jxfzs2wfX5byMp2X3U/\r\n' +
    ' 5XUXGx7qusDgHQGs7Jk9W8CW1fuSWUgN4w==\r\n' +
    'Key-Info: RSA,\r\n' +
    ' I3rRIGXUGWAF8js5wCzRTkdhO34PTHdRZY9Tuvm03M+NM7fx6qc5udixps2Lng0+\r\n' +
    ' wGrtiUm/ovtKdinz6ZQ/aQ==\r\n' +
    'Issuer-Certificate:\r\n' +
    ' MIIB3DCCAUgCAQowDQYJKoZIhvcNAQECBQAwTzELMAkGA1UEBhMCVVMxIDAeBgNV\r\n' +
    ' BAoTF1JTQSBEYXRhIFNlY3VyaXR5LCBJbmMuMQ8wDQYDVQQLEwZCZXRhIDExDTAL\r\n' +
    ' BgNVBAsTBFRMQ0EwHhcNOTEwOTAxMDgwMDAwWhcNOTIwOTAxMDc1OTU5WjBRMQsw\r\n' +
    ' CQYDVQQGEwJVUzEgMB4GA1UEChMXUlNBIERhdGEgU2VjdXJpdHksIEluYy4xDzAN\r\n' +
    ' BgNVBAsTBkJldGEgMTEPMA0GA1UECxMGTk9UQVJZMHAwCgYEVQgBAQICArwDYgAw\r\n' +
    ' XwJYCsnp6lQCxYykNlODwutF/jMJ3kL+3PjYyHOwk+/9rLg6X65B/LD4bJHtO5XW\r\n' +
    ' cqAz/7R7XhjYCm0PcqbdzoACZtIlETrKrcJiDYoP+DkZ8k1gCk7hQHpbIwIDAQAB\r\n' +
    ' MA0GCSqGSIb3DQEBAgUAA38AAICPv4f9Gx/tY4+p+4DB7MV+tKZnvBoy8zgoMGOx\r\n' +
    ' dD2jMZ/3HsyWKWgSF0eH/AJB3qr9zosG47pyMnTf3aSy2nBO7CMxpUWRBcXUpE+x\r\n' +
    ' EREZd9++32ofGBIXaialnOgVUn0OzSYgugiQ077nJLDUj0hQehCizEs5wUJ35a5h\r\n' +
    'MIC-Info: RSA-MD5,RSA,\r\n' +
    ' UdFJR8u/TIGhfH65ieewe2lOW4tooa3vZCvVNGBZirf/7nrgzWDABz8w9NsXSexv\r\n' +
    ' AjRFbHoNPzBuxwmOAFeA0HJszL4yBvhG\r\n' +
    'Recipient-ID-Asymmetric:\r\n' +
    ' MFExCzAJBgNVBAYTAlVTMSAwHgYDVQQKExdSU0EgRGF0YSBTZWN1cml0eSwgSW5j\r\n' +
    ' LjEPMA0GA1UECxMGQmV0YSAxMQ8wDQYDVQQLEwZOT1RBUlk=,66\r\n' +
    'Key-Info: RSA,\r\n' +
    ' O6BS1ww9CTyHPtS3bMLD+L0hejdvX6Qv1HK2ds2sQPEaXhX8EhvVphHYTjwekdWv\r\n' +
    ' 7x0Z3Jx2vTAhOYHMcqqCjA==\r\n' +
    '\r\n' +
    'qeWlj/YJ2Uf5ng9yznPbtD0mYloSwIuV9FRYx+gzY+8iXd/NQrXHfi6/MhPfPF3d\r\n' +
    'jIqCJAxvld2xgqQimUzoS1a4r7kQQ5c/Iua4LqKeq3ciFzEv/MbZhA==\r\n' +
    '-----END PRIVACY-ENHANCED MESSAGE-----\r\n' +
    '-----BEGIN RSA PRIVATE KEY-----\r\n' +
    'MIIBPAIBAAJBALjXU+IdHkSkdBscgXf+EBoa55ruAIsU50uDFjFBkp+rWFt5AOGF\r\n' +
    '9xL1/HNIby5M64BCw021nJTZKEOmXKdmzYsCAwEAAQJBAApyYRNOgf9vLAC8Q7T8\r\n' +
    'bvyKuLxQ50b1D319EywFgLv1Yn0s/F9F+Rew6c04Q0pIqmuOGUM7z94ul/y5OlNJ\r\n' +
    '2cECIQDveEW1ib2+787l7Y0tMeDzf/HQl4MAWdcxXWOeUFK+7QIhAMWZsukutEn9\r\n' +
    '9/yqFMt8bL/dclfNn1IAgUL4+dMJ7zdXAiEAhaxGhVKxN28XuCOFhe/s2R/XdQ/O\r\n' +
    'UZjU1bqCzDGcLvUCIGYmxu71Tg7SVFkyM/3eHPozKOFrU2m5CRnuTHhlMl2RAiEA\r\n' +
    '0vhM5TEmmNWz0anPVabqDj9TA0z5MsDJQcn5NmO9xnw=\r\n' +
    '-----END RSA PRIVATE KEY-----\r\n';

  var _csrWithNew = '-----BEGIN NEW CERTIFICATE REQUEST-----\r\n' +
    'MIIE9jCCAt4CAQAwfjELMAkGA1UEBhMCVVMxETAPBgNVBAgMCFZpcmdpbmlhMRMw\r\n' +
    'EQYDVQQHDApCbGFja3NidXJnMR0wGwYDVQQKDBREaWdpdGFsIEJhemFhciwgSW5j\r\n' +
    'LjEMMAoGA1UECwwDT1NTMRowGAYDVQQDDBFkaWdpdGFsYmF6YWFyLmNvbTCCAiIw\r\n' +
    'DQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAKbqOZ0oC5L+GFnuvwuWnq5J/wxQ\r\n' +
    '6upw5qvA+zfHZYkqdC170OYKsfC67/W6591631xGhVden26/BdxilpeSX1hFVqPF\r\n' +
    'IND7KJvo039QdFQzmzBgqcY5cr11OT9jYjoQMPCehRmbmv6RNaKqTdITMrGZMFzk\r\n' +
    'HFWfshuY71A0+wlz2pOzi79qL7tdcm5s6Whge3/0AAZi19Ze148vCH+HHnbQ7jMH\r\n' +
    'bGJlFZhvGYd2D/clCVnG4w4mCX6scMBZXtf4k1qZAuyhEpTJl8vxCExQs2iCN8lw\r\n' +
    '4tEJH979MQsTDCNf5EZOBzMa4tJtybvQcmFQT2Xjb/8qYT0GyBP+XyJ6nmY3S0R2\r\n' +
    'xZtIsuKlayTw1GG/cYg3OC73G1lbVFLYLh1R+nEs14XX5Dj3J0zTxLeWewFIL7FP\r\n' +
    'D77oRqTHoHNIWz3SJ3S0OTqCYr+5h4vjUOCyXdjCZMZSFOWfCjcMIqcUsysj05gL\r\n' +
    'YBw5z+ZUn17zEEKBuq1tjS1UInbLPBbDMYc1P0NAO5UltdpOs0FPXWgHtzpVoYgZ\r\n' +
    '7W2mXSTgP3xfVicWK6SBP0ejJmcgt4eB5gKidfg0t1BbB/4TgHLrDgGZapVA4DrX\r\n' +
    'agUxalhOrvV0Pm3zWdn6DNGNQbtm0xOebzEFL2bDRangK3OnA4EtOMj39cK2f4bY\r\n' +
    '6ENG38DrC/ctvFmHAgMBAAGgMzAxBgkqhkiG9w0BCQ4xJDAiMAsGA1UdDwQEAwIE\r\n' +
    'MDATBgNVHSUEDDAKBggrBgEFBQcDATANBgkqhkiG9w0BAQsFAAOCAgEAGXNXqKmv\r\n' +
    'Dzkvm+ZTTmwsjf8zlCp1M+QtPSvCMGGUJtqwIFarIKc1H5ZIyfh3p+ws1xDFw0ZK\r\n' +
    'xPyIleeCqMVPAL9me4l8oaQ2IoQ917rmcsdfbPh3/8JkU5rotoRBW0JtsMTx5A6U\r\n' +
    '7FluYFeKVTM1GZo3TpMhG7NZFePtIJfP/hPwtNnIrBkMOLmvyfN68UO1uhazx5/a\r\n' +
    'Uanp1JF9+05hwNSIL/R6TC/RQdeA5b3fycDPfhHhot7Bs/FczgF6I7Qrmyb4pzmR\r\n' +
    'e0knYlOucs0CsV/qj2K2Iouu0lWA0nZQQsbBtvN8dExYZpGPl4LJqNGYF4rLsoep\r\n' +
    'VyDD79rwCM6oqYbQ6GXQJdzXnQoAJTTFyg8bGmj9osBaSb8WKfz1VspnHzsbryxT\r\n' +
    'LPCI9Drg9kB28f7PGN0KWZnmWgD2qV/UuVPjxNhHTC8nEHCQP0gPeHrRgCyhDT4n\r\n' +
    'WPluKuX1B+xO5aOXOSmKcHNufDrN1l/ErhOvYeAimPq1Ag74Z946s27fO0M00kHK\r\n' +
    '+ex8zj29okA0QSsJuCVbOA1tFlyoRd7apN/z1mpcvpb+TDZgdH/HFyrMK1bH2J5u\r\n' +
    'I1iuhuP3g2HSdjLC0wuUA4u73WcbcH7X9tnAHymFgGa5pNUlRPllbIRWvCM+7UaY\r\n' +
    'x6n+naGYblpSHXiboXRsuGWUtTjvqNVdOxA=\r\n' +
    '-----END NEW CERTIFICATE REQUEST-----\r\n';

  var _csrWithoutNew = '-----BEGIN CERTIFICATE REQUEST-----\r\n' +
    'MIIE9jCCAt4CAQAwfjELMAkGA1UEBhMCVVMxETAPBgNVBAgMCFZpcmdpbmlhMRMw\r\n' +
    'EQYDVQQHDApCbGFja3NidXJnMR0wGwYDVQQKDBREaWdpdGFsIEJhemFhciwgSW5j\r\n' +
    'LjEMMAoGA1UECwwDT1NTMRowGAYDVQQDDBFkaWdpdGFsYmF6YWFyLmNvbTCCAiIw\r\n' +
    'DQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAKbqOZ0oC5L+GFnuvwuWnq5J/wxQ\r\n' +
    '6upw5qvA+zfHZYkqdC170OYKsfC67/W6591631xGhVden26/BdxilpeSX1hFVqPF\r\n' +
    'IND7KJvo039QdFQzmzBgqcY5cr11OT9jYjoQMPCehRmbmv6RNaKqTdITMrGZMFzk\r\n' +
    'HFWfshuY71A0+wlz2pOzi79qL7tdcm5s6Whge3/0AAZi19Ze148vCH+HHnbQ7jMH\r\n' +
    'bGJlFZhvGYd2D/clCVnG4w4mCX6scMBZXtf4k1qZAuyhEpTJl8vxCExQs2iCN8lw\r\n' +
    '4tEJH979MQsTDCNf5EZOBzMa4tJtybvQcmFQT2Xjb/8qYT0GyBP+XyJ6nmY3S0R2\r\n' +
    'xZtIsuKlayTw1GG/cYg3OC73G1lbVFLYLh1R+nEs14XX5Dj3J0zTxLeWewFIL7FP\r\n' +
    'D77oRqTHoHNIWz3SJ3S0OTqCYr+5h4vjUOCyXdjCZMZSFOWfCjcMIqcUsysj05gL\r\n' +
    'YBw5z+ZUn17zEEKBuq1tjS1UInbLPBbDMYc1P0NAO5UltdpOs0FPXWgHtzpVoYgZ\r\n' +
    '7W2mXSTgP3xfVicWK6SBP0ejJmcgt4eB5gKidfg0t1BbB/4TgHLrDgGZapVA4DrX\r\n' +
    'agUxalhOrvV0Pm3zWdn6DNGNQbtm0xOebzEFL2bDRangK3OnA4EtOMj39cK2f4bY\r\n' +
    '6ENG38DrC/ctvFmHAgMBAAGgMzAxBgkqhkiG9w0BCQ4xJDAiMAsGA1UdDwQEAwIE\r\n' +
    'MDATBgNVHSUEDDAKBggrBgEFBQcDATANBgkqhkiG9w0BAQsFAAOCAgEAGXNXqKmv\r\n' +
    'Dzkvm+ZTTmwsjf8zlCp1M+QtPSvCMGGUJtqwIFarIKc1H5ZIyfh3p+ws1xDFw0ZK\r\n' +
    'xPyIleeCqMVPAL9me4l8oaQ2IoQ917rmcsdfbPh3/8JkU5rotoRBW0JtsMTx5A6U\r\n' +
    '7FluYFeKVTM1GZo3TpMhG7NZFePtIJfP/hPwtNnIrBkMOLmvyfN68UO1uhazx5/a\r\n' +
    'Uanp1JF9+05hwNSIL/R6TC/RQdeA5b3fycDPfhHhot7Bs/FczgF6I7Qrmyb4pzmR\r\n' +
    'e0knYlOucs0CsV/qj2K2Iouu0lWA0nZQQsbBtvN8dExYZpGPl4LJqNGYF4rLsoep\r\n' +
    'VyDD79rwCM6oqYbQ6GXQJdzXnQoAJTTFyg8bGmj9osBaSb8WKfz1VspnHzsbryxT\r\n' +
    'LPCI9Drg9kB28f7PGN0KWZnmWgD2qV/UuVPjxNhHTC8nEHCQP0gPeHrRgCyhDT4n\r\n' +
    'WPluKuX1B+xO5aOXOSmKcHNufDrN1l/ErhOvYeAimPq1Ag74Z946s27fO0M00kHK\r\n' +
    '+ex8zj29okA0QSsJuCVbOA1tFlyoRd7apN/z1mpcvpb+TDZgdH/HFyrMK1bH2J5u\r\n' +
    'I1iuhuP3g2HSdjLC0wuUA4u73WcbcH7X9tnAHymFgGa5pNUlRPllbIRWvCM+7UaY\r\n' +
    'x6n+naGYblpSHXiboXRsuGWUtTjvqNVdOxA=\r\n' +
    '-----END CERTIFICATE REQUEST-----\r\n';

  describe('pem', function() {
    it('should decode and re-encode PEM messages', function() {
      var msgs = PEM.decode(_input);

      var output = '';
      for(var i = 0; i < msgs.length; ++i) {
        output += PEM.encode(msgs[i]);
      }

      ASSERT.equal(output, _input);
    });

    it('should decode a CSR from PEM with NEW in the labels', function() {
      var csrs = PEM.decode(_csrWithNew);
      for(var i = 0; i < csrs.length; ++i) {
        ASSERT.equal(csrs[i].type, 'CERTIFICATE REQUEST');
      }
    });

    it('should decode a CSR from PEM without NEW in the labels', function() {
      var csrs = PEM.decode(_csrWithoutNew);
      for(var i = 0; i < csrs.length; ++i) {
        ASSERT.equal(csrs[i].type, 'CERTIFICATE REQUEST');
      }
    });
  });
})();
