(function() {

function Tests(ASSERT, PKCS7, PKI, AES, DES, UTIL) {
  var _pem = {
    p7: '-----BEGIN PKCS7-----\r\n' +
      'MIICTgYJKoZIhvcNAQcDoIICPzCCAjsCAQAxggHGMIIBwgIBADCBqTCBmzELMAkG\r\n' +
      'A1UEBhMCREUxEjAQBgNVBAgMCUZyYW5jb25pYTEQMA4GA1UEBwwHQW5zYmFjaDEV\r\n' +
      'MBMGA1UECgwMU3RlZmFuIFNpZWdsMRIwEAYDVQQLDAlHZWllcmxlaW4xFjAUBgNV\r\n' +
      'BAMMDUdlaWVybGVpbiBERVYxIzAhBgkqhkiG9w0BCQEWFHN0ZXNpZUBicm9rZW5w\r\n' +
      'aXBlLmRlAgkA1FQcQNg14vMwDQYJKoZIhvcNAQEBBQAEggEAJhWQz5SniCd1w3A8\r\n' +
      'uKVZEfc8Tp21I7FMfFqou+UOVsZCq7kcEa9uv2DIj3o7zD8wbLK1fuyFi4SJxTwx\r\n' +
      'kR0a6V4bbonIpXPPJ1f615dc4LydAi2tv5w14LJ1Js5XCgGVnkAmQHDaW3EHXB7X\r\n' +
      'T4w9PR3+tcS/5YAnWaM6Es38zCKHd7TnHpuakplIkwSK9rBFAyA1g/IyTPI+ktrE\r\n' +
      'EHcVuJcz/7eTlF6wJEa2HL8F1TVWuL0p/0GsJP/8y0MYGdCdtr+TIVo//3YGhoBl\r\n' +
      'N4tnheFT/jRAzfCZtflDdgAukW24CekrJ1sG2M42p5cKQ5rGFQtzNy/n8EjtUutO\r\n' +
      'HD5YITBsBgkqhkiG9w0BBwEwHQYJYIZIAWUDBAEqBBBmlpfy3WrYj3uWW7+xNEiH\r\n' +
      'gEAm2mfSF5xFPLEqqFkvKTM4w8PfhnF0ehmfQNApvoWQRQanNWLCT+Q9GHx6DCFj\r\n' +
      'TUHl+53x88BrCl1E7FhYPs92\r\n' +
      '-----END PKCS7-----\r\n',
    certificate: '-----BEGIN CERTIFICATE-----\r\n' +
      'MIIDtDCCApwCCQDUVBxA2DXi8zANBgkqhkiG9w0BAQUFADCBmzELMAkGA1UEBhMC\r\n' +
      'REUxEjAQBgNVBAgMCUZyYW5jb25pYTEQMA4GA1UEBwwHQW5zYmFjaDEVMBMGA1UE\r\n' +
      'CgwMU3RlZmFuIFNpZWdsMRIwEAYDVQQLDAlHZWllcmxlaW4xFjAUBgNVBAMMDUdl\r\n' +
      'aWVybGVpbiBERVYxIzAhBgkqhkiG9w0BCQEWFHN0ZXNpZUBicm9rZW5waXBlLmRl\r\n' +
      'MB4XDTEyMDMxODIyNTc0M1oXDTEzMDMxODIyNTc0M1owgZsxCzAJBgNVBAYTAkRF\r\n' +
      'MRIwEAYDVQQIDAlGcmFuY29uaWExEDAOBgNVBAcMB0Fuc2JhY2gxFTATBgNVBAoM\r\n' +
      'DFN0ZWZhbiBTaWVnbDESMBAGA1UECwwJR2VpZXJsZWluMRYwFAYDVQQDDA1HZWll\r\n' +
      'cmxlaW4gREVWMSMwIQYJKoZIhvcNAQkBFhRzdGVzaWVAYnJva2VucGlwZS5kZTCC\r\n' +
      'ASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMsAbQ4fWevHqP1K1y/ewpMS\r\n' +
      '3vYovBto7IsKBq0v3NmC2kPf3NhyaSKfjOOS5uAPONLffLck+iGdOLLFia6OSpM6\r\n' +
      '0tyQIV9lHoRh7fOEYORab0Z+aBUZcEGT9yotBOraX1YbKc5f9XO+80eG4XYvb5ua\r\n' +
      '1NHrxWqe4w2p3zGJCKO+wHpvGkbKz0nfu36jwWz5aihfHi9hp/xs8mfH86mIKiD7\r\n' +
      'f2X2KeZ1PK9RvppA0X3lLb2VLOqMt+FHWicyZ/wjhQZ4oW55ln2yYJUQ+adlgaYn\r\n' +
      'PrtnsxmbTxM+99oF0F2/HmGrNs8nLZSva1Vy+hmjmWz6/O8ZxhiIj7oBRqYcAocC\r\n' +
      'AwEAATANBgkqhkiG9w0BAQUFAAOCAQEAvfvtu31GFBO5+mFjPAoR4BlzKq/H3EPO\r\n' +
      'qS8cm/TjHgDRALwSnwKYCFs/bXqE4iOTD6otV4TusX3EPbqL2vzZQEcZn6paU/oZ\r\n' +
      'ZVXwQqMqY5tf2teQiNxqxNmSIEPRHOr2QVBVIx2YF4Po89KGUqJ9u/3/10lDqRwp\r\n' +
      'sReijr5UKv5aygEcnwcW8+Ne4rTx934UDsutKG20dr5trZfWQRVS9fS9CFwJehEX\r\n' +
      'HAMUc/0++80NhfQthmWZWlWM1R3dr4TrIPtWdn5z0MtGeDvqBk7HjGrhcVS6kAsy\r\n' +
      'Z9y/lfLPjBuxlQAHztEJCWgI4TW3/RLhgfg2gI1noM2n84Cdmisfkg==\r\n' +
      '-----END CERTIFICATE-----\r\n',
    privateKey: '-----BEGIN RSA PRIVATE KEY-----\r\n' +
      'MIIEowIBAAKCAQEAywBtDh9Z68eo/UrXL97CkxLe9ii8G2jsiwoGrS/c2YLaQ9/c\r\n' +
      '2HJpIp+M45Lm4A840t98tyT6IZ04ssWJro5KkzrS3JAhX2UehGHt84Rg5FpvRn5o\r\n' +
      'FRlwQZP3Ki0E6tpfVhspzl/1c77zR4bhdi9vm5rU0evFap7jDanfMYkIo77Aem8a\r\n' +
      'RsrPSd+7fqPBbPlqKF8eL2Gn/GzyZ8fzqYgqIPt/ZfYp5nU8r1G+mkDRfeUtvZUs\r\n' +
      '6oy34UdaJzJn/COFBnihbnmWfbJglRD5p2WBpic+u2ezGZtPEz732gXQXb8eYas2\r\n' +
      'zyctlK9rVXL6GaOZbPr87xnGGIiPugFGphwChwIDAQABAoIBAAjMA+3QvfzRsikH\r\n' +
      'zTtt09C7yJ2yNjSZ32ZHEPMAV/m1CfBXCyL2EkhF0b0q6IZdIoFA3g6xs4UxYvuc\r\n' +
      'Q9Mkp2ap7elQ9aFEqIXkGIOtAOXkZV4QrEH90DeHSfax7LygqfD5TF59Gg3iAHjh\r\n' +
      'B3Qvqg58LyzJosx0BjLZYaqr3Yv67GkqyflpF/roPGdClHpahAi5PBkHiNhNTAUU\r\n' +
      'LJRGvMegXGZkUKgGMAiGCk0N96OZwrinMKO6YKGdtgwVWC2wbJY0trElaiwXozSt\r\n' +
      'NmP6KTQp94C7rcVO6v1lZiOfhBe5Kc8QHUU+GYydgdjqm6Rdow/yLHOALAVtXSeb\r\n' +
      'U+tPfcECgYEA6Qi+qF+gtPincEDBxRtoKwAlRkALt8kly8bYiGcUmd116k/5bmPw\r\n' +
      'd0tBUOQbqRa1obYC88goOVzp9LInAcBSSrexhVaPAF4nrkwYXMOq+76MiH17WUfQ\r\n' +
      'MgVM2IB48PBjNk1s3Crj6j1cxxkctqmCnVaI9HlU2PPZ3xjaklfv/NsCgYEA3wH8\r\n' +
      'mehUhiAp7vuhd+hfomFw74cqgHC9v0saiYGckpMafh9MJGc4U5GrN1kYeb/CFkSx\r\n' +
      '1hOytD3YBKoaKKoYagaMQcjxf6HnEF0f/5OiQkUQpWmgC9lNnE4XTWjnwqaTS5L9\r\n' +
      'D+H50SiI3VjHymGXTRJeKpAIwV74AxxrnVofqsUCgYAwmL1B2adm9g/c7fQ6yatg\r\n' +
      'hEhBrSuEaTMzmsUfNPfr2m4zrffjWH4WMqBtYRSPn4fDMHTPJ+eThtfXSqutxtCi\r\n' +
      'ekpP9ywdNIVr6LyP49Ita6Bc+mYVyU8Wj1pmL+yIumjGM0FHbL5Y4/EMKCV/xjvR\r\n' +
      '2fD3orHaCIhf6QvzxtjqTwKBgFm6UemXKlMhI94tTsWRMNGEBU3LA9XUBvSuAkpr\r\n' +
      'ZRUwrQssCpXnFinBxbMqXQe3mR8emrM5D8En1P/jdU0BS3t1kP9zG4AwI2lZHuPV\r\n' +
      'ggbKBS2Y9zVtRKXsYcHawM13+nIA/WNjmAGJHrB45UJPy/HNvye+9lbfoEiYKdCR\r\n' +
      'D4bFAoGBAIm9jcZkIwLa9kLAWH995YYYSGRY4KC29XZr2io2mog+BAjhFt1sqebt\r\n' +
      'R8sRHNiIP2mcUECMOcaS+tcayi+8KTHWxIEed9qDmFu6XBbePfe/L6yxPSagcixH\r\n' +
      'BK0KuK/fgTPvZCmIs8hUIC+AxhXKnqn4fIWoO54xLsALc0gEjs2d\r\n' +
      '-----END RSA PRIVATE KEY-----\r\n',
    encryptedData: '-----BEGIN PKCS7-----\r\n' +
      'MIGHBgkqhkiG9w0BBwagejB4AgEAMHMGCSqGSIb3DQEHATAUBggqhkiG9w0DBwQI\r\n' +
      'upMFou5X3DWAUAqObuHSlewM0ZtHzWk9MAmtYb7MSb//OBMKVfLCdbmrS5BpKm9J\r\n' +
      'gzwiDR5Od7xgfkqasLS2lOdKAvJ5jZjjTpAyrjBKpShqK9gtXDuO0zH+\r\n' +
      '-----END PKCS7-----\r\n',
    p7IndefiniteLength: '-----BEGIN PKCS7-----\r\n' +
      'MIAGCSqGSIb3DQEHA6CAMIACAQAxggHGMIIBwgIBADCBqTCBmzELMAkGA1UEBhMC\r\n' +
      'REUxEjAQBgNVBAgMCUZyYW5jb25pYTEQMA4GA1UEBwwHQW5zYmFjaDEVMBMGA1UE\r\n' +
      'CgwMU3RlZmFuIFNpZWdsMRIwEAYDVQQLDAlHZWllcmxlaW4xFjAUBgNVBAMMDUdl\r\n' +
      'aWVybGVpbiBERVYxIzAhBgkqhkiG9w0BCQEWFHN0ZXNpZUBicm9rZW5waXBlLmRl\r\n' +
      'AgkA1FQcQNg14vMwDQYJKoZIhvcNAQEBBQAEggEAlWCH+E25c4jfff+m0eAxxMmE\r\n' +
      'WWaftdsk4ZpAVAr7HsvxJ35bj1mhwTh7rBTg929JBKt6ZaQ4I800jCNxD2O40V6z\r\n' +
      'lB7JNRqzgBwfeuU2nV6FB7v1984NBi1jQx6EfxOcusE6RL/63HqJdFbmq3Tl55gF\r\n' +
      'dm3JdjmHbCXqwPhuwOXU4yhkpV1RJcrYhPLe3OrLAH7ZfoE0nPJPOX9HPTZ6ReES\r\n' +
      'NToS7I9D9k7rCa8fAP7pgjO96GJGBtCHG1VXB9NX4w+xRDbgVPOeHXqqxwZhqpW2\r\n' +
      'usBU4+B+MnFLjquOPoySXFfdJFwTP61TPClUdyIne5FFP6EYf98mdtnkjxHo1TCA\r\n' +
      'BgkqhkiG9w0BBwEwFAYIKoZIhvcNAwcECFNtpqBmU3M9oIAESM+yyQLkreETS0Kc\r\n' +
      'o01yl6dqqNBczH5FNTK88ypz38/jzjo47+DURlvGzjHJibiDsCz9KyiVmgbRrtvH\r\n' +
      '08rfnMbrU+grCkkx9wQI1GnLrYhr87oAAAAAAAAAAAAA\r\n' +
      '-----END PKCS7-----\r\n',
    p73des: '-----BEGIN PKCS7-----\r\n' +
      'MIICTQYJKoZIhvcNAQcDoIICPjCCAjoCAQAxggHGMIIBwgIBADCBqTCBmzELMAkG\r\n' +
      'A1UEBhMCREUxEjAQBgNVBAgMCUZyYW5jb25pYTEQMA4GA1UEBwwHQW5zYmFjaDEV\r\n' +
      'MBMGA1UECgwMU3RlZmFuIFNpZWdsMRIwEAYDVQQLDAlHZWllcmxlaW4xFjAUBgNV\r\n' +
      'BAMMDUdlaWVybGVpbiBERVYxIzAhBgkqhkiG9w0BCQEWFHN0ZXNpZUBicm9rZW5w\r\n' +
      'aXBlLmRlAgkA1FQcQNg14vMwDQYJKoZIhvcNAQEBBQAEggEAS6K+sQvdKcK6YafJ\r\n' +
      'maDPjBzyjf5jtBgVrFgBXTCRIp/Z2zAXa70skfxhbwTgmilYTacA7jPGRrnLmvBc\r\n' +
      'BjhyCKM3dRUyYgh1K1ka0w1prvLmRk6Onf5df1ZQn3AJMIujJZcCOhbV1ByLInve\r\n' +
      'xn02KNHstGmdHM/JGyPCp+iYGprhUozVSpNCKS+R33EbsT0sAxamfqdAblT9+5Qj\r\n' +
      '4CABvW11a1clPV7STwBbAKbZaLs8mDeoWP0yHvBtJ7qzZdSgJJA2oU7SDv4icwEe\r\n' +
      'Ahccbe2HWkLRw8G5YG9XcWx5PnQQhhnXMxkLoSMIYxItyL/cRORbpDohd+otAo66\r\n' +
      'WLH1ODBrBgkqhkiG9w0BBwEwFAYIKoZIhvcNAwcECD5EWJMv1fd7gEj1w3WM1KsM\r\n' +
      'L8GDk9JoqA8t9v3oXCT0nAMXoNpHZMnv+0UHHVljlSXBTQxwUP5VMY/ddquJ5O3N\r\n' +
      'rDEqqJuHB+KPIsW1kxrdplU=\r\n' +
      '-----END PKCS7-----\r\n',
    degenerateP7: '-----BEGIN PKCS7-----\r\n' +
      'MIID4wYJKoZIhvcNAQcCoIID1DCCA9ACAQExADALBgkqhkiG9w0BBwGgggO4MIID\r\n' +
      'tDCCApwCCQDUVBxA2DXi8zANBgkqhkiG9w0BAQUFADCBmzELMAkGA1UEBhMCREUx\r\n' +
      'EjAQBgNVBAgMCUZyYW5jb25pYTEQMA4GA1UEBwwHQW5zYmFjaDEVMBMGA1UECgwM\r\n' +
      'U3RlZmFuIFNpZWdsMRIwEAYDVQQLDAlHZWllcmxlaW4xFjAUBgNVBAMMDUdlaWVy\r\n' +
      'bGVpbiBERVYxIzAhBgkqhkiG9w0BCQEWFHN0ZXNpZUBicm9rZW5waXBlLmRlMB4X\r\n' +
      'DTEyMDMxODIyNTc0M1oXDTEzMDMxODIyNTc0M1owgZsxCzAJBgNVBAYTAkRFMRIw\r\n' +
      'EAYDVQQIDAlGcmFuY29uaWExEDAOBgNVBAcMB0Fuc2JhY2gxFTATBgNVBAoMDFN0\r\n' +
      'ZWZhbiBTaWVnbDESMBAGA1UECwwJR2VpZXJsZWluMRYwFAYDVQQDDA1HZWllcmxl\r\n' +
      'aW4gREVWMSMwIQYJKoZIhvcNAQkBFhRzdGVzaWVAYnJva2VucGlwZS5kZTCCASIw\r\n' +
      'DQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMsAbQ4fWevHqP1K1y/ewpMS3vYo\r\n' +
      'vBto7IsKBq0v3NmC2kPf3NhyaSKfjOOS5uAPONLffLck+iGdOLLFia6OSpM60tyQ\r\n' +
      'IV9lHoRh7fOEYORab0Z+aBUZcEGT9yotBOraX1YbKc5f9XO+80eG4XYvb5ua1NHr\r\n' +
      'xWqe4w2p3zGJCKO+wHpvGkbKz0nfu36jwWz5aihfHi9hp/xs8mfH86mIKiD7f2X2\r\n' +
      'KeZ1PK9RvppA0X3lLb2VLOqMt+FHWicyZ/wjhQZ4oW55ln2yYJUQ+adlgaYnPrtn\r\n' +
      'sxmbTxM+99oF0F2/HmGrNs8nLZSva1Vy+hmjmWz6/O8ZxhiIj7oBRqYcAocCAwEA\r\n' +
      'ATANBgkqhkiG9w0BAQUFAAOCAQEAvfvtu31GFBO5+mFjPAoR4BlzKq/H3EPOqS8c\r\n' +
      'm/TjHgDRALwSnwKYCFs/bXqE4iOTD6otV4TusX3EPbqL2vzZQEcZn6paU/oZZVXw\r\n' +
      'QqMqY5tf2teQiNxqxNmSIEPRHOr2QVBVIx2YF4Po89KGUqJ9u/3/10lDqRwpsRei\r\n' +
      'jr5UKv5aygEcnwcW8+Ne4rTx934UDsutKG20dr5trZfWQRVS9fS9CFwJehEXHAMU\r\n' +
      'c/0++80NhfQthmWZWlWM1R3dr4TrIPtWdn5z0MtGeDvqBk7HjGrhcVS6kAsyZ9y/\r\n' +
      'lfLPjBuxlQAHztEJCWgI4TW3/RLhgfg2gI1noM2n84CdmisfkjEA\r\n' +
      '-----END PKCS7-----\r\n',
    signedDataNoAttrs: '-----BEGIN PKCS7-----\r\n' +
      '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\r\n' +
      'JYiOgKdXRs1MdQqnl0Q=\r\n' +
      '-----END PKCS7-----\r\n',
    signedDataWithAttrsUTCTime: '-----BEGIN PKCS7-----\r\n' +
      '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\r\n' +
      'gwbBcDl+50dPc2TncPe0uPfHgo5/Pr2ckA==\r\n' +
      '-----END PKCS7-----\r\n',
    signedDataWithAttrsGeneralizedTime: '-----BEGIN PKCS7-----\r\n' +
      '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\r\n' +
      'JxV3HaZ/Jvfnx9uH9wpFYg5yFX6PBLxlHarf\r\n' +
      '-----END PKCS7-----\r\n'
  };

  describe('pkcs7', function() {
    it('should import message from PEM', function() {
      var p7 = PKCS7.messageFromPem(_pem.p7);

      ASSERT.equal(p7.type, PKI.oids.envelopedData);
      ASSERT.equal(p7.version, 0);

      ASSERT.equal(p7.recipients.length, 1);
      ASSERT.equal(p7.recipients[0].version, 0);
      ASSERT.equal(p7.recipients[0].serialNumber, '00d4541c40d835e2f3');

      // Test converted RDN, which is constructed of seven parts.
      ASSERT.equal(p7.recipients[0].issuer.length, 7);
      ASSERT.equal(p7.recipients[0].issuer[0].type, '2.5.4.6');
      ASSERT.equal(p7.recipients[0].issuer[0].value, 'DE');
      ASSERT.equal(p7.recipients[0].issuer[1].type, '2.5.4.8');
      ASSERT.equal(p7.recipients[0].issuer[1].value, 'Franconia');
      ASSERT.equal(p7.recipients[0].issuer[2].type, '2.5.4.7');
      ASSERT.equal(p7.recipients[0].issuer[2].value, 'Ansbach');
      ASSERT.equal(p7.recipients[0].issuer[3].type, '2.5.4.10');
      ASSERT.equal(p7.recipients[0].issuer[3].value, 'Stefan Siegl');
      ASSERT.equal(p7.recipients[0].issuer[4].type, '2.5.4.11');
      ASSERT.equal(p7.recipients[0].issuer[4].value, 'Geierlein');
      ASSERT.equal(p7.recipients[0].issuer[5].type, '2.5.4.3');
      ASSERT.equal(p7.recipients[0].issuer[5].value, 'Geierlein DEV');
      ASSERT.equal(p7.recipients[0].issuer[6].type, '1.2.840.113549.1.9.1');
      ASSERT.equal(p7.recipients[0].issuer[6].value, 'stesie@brokenpipe.de');

      ASSERT.equal(p7.recipients[0].encryptedContent.algorithm, PKI.oids.rsaEncryption);
      ASSERT.equal(p7.recipients[0].encryptedContent.content.length, 256);

      ASSERT.equal(p7.encryptedContent.algorithm, PKI.oids['aes256-CBC']);
      ASSERT.equal(p7.encryptedContent.parameter.data.length, 16);  // IV
    });

    it('should import indefinite length message from PEM', function() {
      ASSERT.doesNotThrow(function() {
        var p7 = PKCS7.messageFromPem(_pem.p7IndefiniteLength);
        ASSERT.equal(p7.type, PKI.oids.envelopedData);
        ASSERT.equal(p7.encryptedContent.parameter.toHex(), '536da6a06653733d');
        ASSERT.equal(p7.encryptedContent.content.length(), 80);
      });
    });

    it('should find recipient by serial number', function() {
      var p7 = PKCS7.messageFromPem(_pem.p7);
      var cert = PKI.certificateFromPem(_pem.certificate);

      var ri = p7.findRecipient(cert);
      ASSERT.equal(ri.serialNumber, '00d4541c40d835e2f3');

      // modify certificate so it doesn't match recipient any more
      cert.serialNumber = '1234567890abcdef42';
      ri = p7.findRecipient(cert);
      ASSERT.equal(ri, null);
    });

    it('should aes-decrypt message', function() {
      var p7 = PKCS7.messageFromPem(_pem.p7);
      var privateKey = PKI.privateKeyFromPem(_pem.privateKey);
      p7.decrypt(p7.recipients[0], privateKey);

      // symmetric key must be 32 bytes long (AES 256 key)
      ASSERT.equal(p7.encryptedContent.key.data.length, 32);
      ASSERT.equal(
        p7.content,
        'Today is Boomtime, the 9th day of Discord in the YOLD 3178\r\n');
    });

    it('should 3des-decrypt message', function() {
      var p7 = PKCS7.messageFromPem(_pem.p73des);
      var privateKey = PKI.privateKeyFromPem(_pem.privateKey);
      p7.decrypt(p7.recipients[0], privateKey);

      // symmetric key must be 24 bytes long (DES3 key)
      ASSERT.equal(p7.encryptedContent.key.data.length, 24);
      ASSERT.equal(
        p7.content,
        'Today is Prickle-Prickle, ' +
        'the 16th day of Discord in the YOLD 3178\r\n');
    });

    it('should add a recipient', function() {
      var p7 = PKCS7.createEnvelopedData();

      // initially there should be no recipients
      ASSERT.equal(p7.recipients.length, 0);

      var cert = PKI.certificateFromPem(_pem.certificate);
      p7.addRecipient(cert);

      ASSERT.equal(p7.recipients.length, 1);
      ASSERT.deepEqual(p7.recipients[0].serialNumber, cert.serialNumber);
      ASSERT.deepEqual(p7.recipients[0].issuer, cert.subject.attributes);
      ASSERT.deepEqual(p7.recipients[0].encryptedContent.key, cert.publicKey);
    });

    it('should aes-encrypt a message', function() {
      var p7 = PKCS7.createEnvelopedData();
      var cert = PKI.certificateFromPem(_pem.certificate);
      var privateKey = PKI.privateKeyFromPem(_pem.privateKey);

      p7.addRecipient(cert);
      p7.content = UTIL.createBuffer('Just a little test');

      // pre-condition, PKCS#7 module should default to AES-256-CBC
      ASSERT.equal(p7.encryptedContent.algorithm, PKI.oids['aes256-CBC']);
      p7.encrypt();

      // since we did not provide a key, a random key should have been created
      // automatically, AES256 requires 32 bytes of key material
      ASSERT.equal(p7.encryptedContent.key.data.length, 32);

      // furthermore an IV must be generated, AES256 has 16 byte IV
      ASSERT.equal(p7.encryptedContent.parameter.data.length, 16);

      // content is 18 bytes long, AES has 16 byte blocksize,
      // with padding that makes 32 bytes
      ASSERT.equal(p7.encryptedContent.content.data.length, 32);

      // RSA encryption should yield 256 bytes
      ASSERT.equal(p7.recipients[0].encryptedContent.content.length, 256);

      // rewind Key & IV
      p7.encryptedContent.key.read = 0;
      p7.encryptedContent.parameter.read = 0;

      // decryption of the asym. encrypted data should reveal the symmetric key
      var decryptedKey = privateKey.decrypt(
        p7.recipients[0].encryptedContent.content);
      ASSERT.equal(decryptedKey, p7.encryptedContent.key.data);

      // decryption of sym. encrypted data should reveal the content
      var ciph = AES.createDecryptionCipher(decryptedKey);
      ciph.start(p7.encryptedContent.parameter);
      ciph.update(p7.encryptedContent.content);
      ciph.finish();
      ASSERT.equal(ciph.output, 'Just a little test');
    });

    it('should 3des-ede-encrypt a message', function() {
      var p7 = PKCS7.createEnvelopedData();
      var cert = PKI.certificateFromPem(_pem.certificate);
      var privateKey = PKI.privateKeyFromPem(_pem.privateKey);

      p7.addRecipient(cert);
      p7.content = UTIL.createBuffer('Just a little test');
      p7.encryptedContent.algorithm = PKI.oids['des-EDE3-CBC'];
      p7.encrypt();

      // since we did not provide a key, a random key should have been created
      // automatically, 3DES-EDE requires 24 bytes of key material
      ASSERT.equal(p7.encryptedContent.key.data.length, 24);

      // furthermore an IV must be generated, DES3 has 8 byte IV
      ASSERT.equal(p7.encryptedContent.parameter.data.length, 8);

      // content is 18 bytes long, DES has 8 byte blocksize,
      // with padding that makes 24 bytes
      ASSERT.equal(p7.encryptedContent.content.data.length, 24);

      // RSA encryption should yield 256 bytes
      ASSERT.equal(p7.recipients[0].encryptedContent.content.length, 256);

      // rewind Key & IV
      p7.encryptedContent.key.read = 0;
      p7.encryptedContent.parameter.read = 0;

      // decryption of the asym. encrypted data should reveal the symmetric key
      var decryptedKey = privateKey.decrypt(
        p7.recipients[0].encryptedContent.content);
      ASSERT.equal(decryptedKey, p7.encryptedContent.key.data);

      // decryption of sym. encrypted data should reveal the content
      var ciph = DES.createDecryptionCipher(decryptedKey);
      ciph.start(p7.encryptedContent.parameter);
      ciph.update(p7.encryptedContent.content);
      ciph.finish();
      ASSERT.equal(ciph.output, 'Just a little test');
    });

    it('should export message to PEM', function() {
      var p7 = PKCS7.createEnvelopedData();
      p7.addRecipient(PKI.certificateFromPem(_pem.certificate));
      p7.content = UTIL.createBuffer('Just a little test');
      p7.encrypt();

      var pem = PKCS7.messageToPem(p7);

      // convert back from PEM to new PKCS#7 object, decrypt, and test
      p7 = PKCS7.messageFromPem(pem);
      p7.decrypt(p7.recipients[0], PKI.privateKeyFromPem(_pem.privateKey));
      ASSERT.equal(p7.content, 'Just a little test');
    });

    it('should decrypt encrypted data from PEM', function() {
      var result = '1f8b08000000000000000b2e494d4bcc5308ce4c4dcfd15130b0b430d4b7343732b03437d05170cc2b4e4a4cced051b034343532d25170492d2d294ecec849cc4b0100bf52f02437000000';
      var key = 'b96e4a4c0a3555d31e1b295647cc5cfe74081918cb7f797b';
      key = UTIL.createBuffer(UTIL.hexToBytes(key));

      ASSERT.doesNotThrow(function() {
        var p7 = PKCS7.messageFromPem(_pem.encryptedData);
        ASSERT.equal(p7.type, PKI.oids.encryptedData);
        ASSERT.equal(p7.encryptedContent.algorithm, PKI.oids['des-EDE3-CBC']);
        ASSERT.equal(p7.encryptedContent.parameter.toHex(), 'ba9305a2ee57dc35');
        ASSERT.equal(p7.encryptedContent.content.length(), 80);

        p7.decrypt(key);
        ASSERT.equal(p7.content.toHex(), result);
      });
    });

    it('should create a degenerate PKCS#7 certificate container', function() {
      var p7 = PKCS7.createSignedData();
      p7.addCertificate(_pem.certificate);
      var pem = PKCS7.messageToPem(p7);
      ASSERT.equal(pem, _pem.degenerateP7);
    });

    it('should create PKCS#7 SignedData with no attributes', function() {
      // verify with:
      // openssl smime -verify -in p7.pem -signer certificate.pem \
      //   -out signedtext.txt -inform PEM -CAfile certificate.pem
      var p7 = PKCS7.createSignedData();
      p7.content = UTIL.createBuffer('To be signed.', 'utf8');
      p7.addCertificate(_pem.certificate);
      p7.addSigner({
        key: PKI.privateKeyFromPem(_pem.privateKey),
        certificate: _pem.certificate,
        digestAlgorithm: PKI.oids.sha256
      });
      p7.sign();
      var pem = PKCS7.messageToPem(p7);
      ASSERT.equal(pem, _pem.signedDataNoAttrs);
    });

    if(typeof define === 'function') {
      // return here for phantomjs; it has date serialization and timezone
      // bugs that prevent the following tests from running properly
      // see: https://github.com/ariya/phantomjs/issues/11712
      return;
    }

    it('should create PKCS#7 SignedData with content-type, message-digest, ' +
      'and signing-time attributes using UTCTime', function() {
      // verify with:
      // openssl smime -verify -in p7.pem -signer certificate.pem \
      //   -out signedtext.txt -inform PEM -CAfile certificate.pem
      var p7 = PKCS7.createSignedData();
      p7.content = UTIL.createBuffer('To be signed.', 'utf8');
      p7.addCertificate(_pem.certificate);
      p7.addSigner({
        key: PKI.privateKeyFromPem(_pem.privateKey),
        certificate: _pem.certificate,
        digestAlgorithm: PKI.oids.sha256,
        authenticatedAttributes: [{
          type: forge.pki.oids.contentType,
          value: forge.pki.oids.data
        }, {
          type: forge.pki.oids.messageDigest
          // value will be auto-populated at signing time
        }, {
          type: forge.pki.oids.signingTime,
          // will be encoded as UTC time because it's >= 1950
          value: new Date('1950-01-01T00:00:00Z')
        }]
      });
      p7.sign();
      var pem = PKCS7.messageToPem(p7);
      ASSERT.equal(pem, _pem.signedDataWithAttrsUTCTime);
    });

    it('should create PKCS#7 SignedData with content-type, message-digest, ' +
      'and signing-time attributes using GeneralizedTime', function() {
      // verify with:
      // openssl smime -verify -in p7.pem -signer certificate.pem \
      //   -out signedtext.txt -inform PEM -CAfile certificate.pem
      var p7 = PKCS7.createSignedData();
      p7.content = UTIL.createBuffer('To be signed.', 'utf8');
      p7.addCertificate(_pem.certificate);
      p7.addSigner({
        key: PKI.privateKeyFromPem(_pem.privateKey),
        certificate: _pem.certificate,
        digestAlgorithm: PKI.oids.sha256,
        authenticatedAttributes: [{
          type: forge.pki.oids.contentType,
          value: forge.pki.oids.data
        }, {
          type: forge.pki.oids.messageDigest
          // value will be auto-populated at signing time
        }, {
          type: forge.pki.oids.signingTime,
          // will be encoded as generalized time because it's before 1950
          value: new Date('1949-12-31T23:59:59Z')
        }]
      });
      p7.sign();
      var pem = PKCS7.messageToPem(p7);
      ASSERT.equal(pem, _pem.signedDataWithAttrsGeneralizedTime);
    });

    // TODO: add a test for Jan 1 2050 once phantomjs 2.0 is out and
    // its date bugs are fixed (generalized time should be used for >= 2050)

    it('should create PKCS#7 SignedData with PEM-encoded private key', function() {
      // verify with:
      // openssl smime -verify -in p7.pem -signer certificate.pem \
      //   -out signedtext.txt -inform PEM -CAfile certificate.pem
      var p7 = PKCS7.createSignedData();
      p7.content = UTIL.createBuffer('To be signed.', 'utf8');
      p7.addCertificate(_pem.certificate);
      p7.addSigner({
        key: _pem.privateKey,
        certificate: _pem.certificate,
        digestAlgorithm: PKI.oids.sha256,
        authenticatedAttributes: [{
          type: forge.pki.oids.contentType,
          value: forge.pki.oids.data
        }, {
          type: forge.pki.oids.messageDigest
          // value will be auto-populated at signing time
        }, {
          type: forge.pki.oids.signingTime,
          // will be encoded as generalized time because it's before 1950
          value: new Date('1949-12-31T23:59:59Z')
        }]
      });
      p7.sign();
      var pem = PKCS7.messageToPem(p7);
      ASSERT.equal(pem, _pem.signedDataWithAttrsGeneralizedTime);
    });

  });
}

// check for AMD
var forge = {};
if(typeof define === 'function') {
  define([
    'forge/pkcs7',
    'forge/pki',
    'forge/aes',
    'forge/des',
    'forge/util'
  ], function(PKCS7, PKI, AES, DES, UTIL) {
    Tests(
      // Global provided by test harness
      ASSERT,
      PKCS7(forge),
      PKI(forge),
      AES(forge),
      DES(forge),
      UTIL(forge)
    );
  });
} else if(typeof module === 'object' && module.exports) {
  // assume NodeJS
  Tests(
    require('assert'),
    require('../../js/pkcs7')(forge),
    require('../../js/pki')(forge),
    require('../../js/aes')(forge),
    require('../../js/des')(forge),
    require('../../js/util')(forge));
}

})();
