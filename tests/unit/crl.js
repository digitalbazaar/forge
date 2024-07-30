var ASSERT = require('assert');
var PKI = require('../../lib/pki');

(function() {
  var _pem = {
    /*caKey: -----BEGIN RSA PRIVATE KEY-----
      MIIEogIBAAKCAQEApgaKzl0MIXjFGykNKOPXuYn0G9lwLJ2eRTRcpqUXiWqwSEAD
      fyK/5qUbed7XgIIPX8j8Cghm4jTqDyVE66sX7fWTqoY4vhfEmVGdhq2Q4niI5xLv
      32Na66KztMGVaB2FYbquwXGN2RopHCcyLQL2krphik4Ftn+CJ6qK38czE2SX4JqM
      SK2kjfvrBAkKUoAeJgqzV/6ICG0T2j7MVeYN8ygee5YQvaBaHgq+rd/nj7naqUNp
      KoWCD49vaIQn0CUx39mCMdCQ/ZjT0ddr10bjIN2Ta7Jf5o6XnIGY38ImpBtuzikp
      zdMEkX+2Jjjo/MS+M9008pZjkbBkDCxvxMPgdwIDAQABAoIBAEetHGDyN8n9jy7m
      HqnQD7Ko1avuSCji1VDwRa2mKY6ocjmG9Vt+X5XOIxoOtD/lJokGRpV4Qh6XlJL8
      VpBd2aNgeaNNdhLPRQ+h9h2OMjYrroMAIHHzPW3sXKQFTSDZWduy0j5ubTxUuHnQ
      jC91j4kSEQk6HOpIiyLf1Du/DpRoj2ktnGO36K5B3AKsbK8vH5xuTZkv0teoghLL
      kMTZGrGEJQzYbDxl8I4gKNfpktpzXzMJU92M0+sRBRJ8SCy+V6QUF8XdKxAZ1aZ7
      7ajumUFzhwWAqLt4D/iDtWo5m+IZXUcAJ+Fb6gSsbh2rTgXZU37dG6v9JerDH1sC
      1wFQiOkCgYEA3DziQYO9N5iUVnFBZ0vbmk2R5QKJ8xL8hL6ZsT6evV1oC2/Jv/Bu
      /iaM6nKQwX+6KzLIcbYJsX5i2M47nIeElT40ZFBJ6FE2NGt1hZNTp+v/iPJG6A4H
      uP7GEq+Ew2SYEDfBXDcrUvrZrGYYZD14+fJ2qD7Pu047U98qQnFwlb8CgYEAwPwY
      nwMrMFlW7fn7aS0uC/RSjPwPzOAqJTBudttPOhYDCuzy+0ktGRnxxUP++xowd2by
      /UrGa5+12r5DnbEQXpOKonB1QXSp+kCwC75alcWseeQqqNy9lDawBS/dNND6+e8h
      g8CFptM3ahjt8oxMVorD9gQHbH9mZ4K0e0p0E0kCgYBTHLbVun2BqZbxODRSYxIw
      nO1d2yNsE9Iv1i3x8Yu+Mq29AybDxFxelPXA1BNEsorzGmsCXowx61wqLUnZvFqQ
      Z7Ul1hbOETe/eH4VNo/vYuRALg4MLJ9FdQAStSIJCsFH/YJ+5mL3Iatbn/u8eGZb
      DOEyhOGn8dH5yNIN2Pl/yQKBgCt8o0+xtxm+CAi4PB8HP0kSVUfPxP+1w8l9kGbY
      JJJCQ41Ct75ITxFI92IsYFjVHfbKDBdnsi6uXpxcI4B1Ver59FOGY+XMFEGAMitz
      SZZWZPdSowpKM64iZKfGkWJFdUi8yiCWUYe2MNaHp5bwZoNZ4a6eWc3pJ3pLyb++
      l0mBAoGADz3D1T/p29qIjqSuwfGoc3Nuto7CGLILt/IPoIJmgbtYql1EeusVpuNK
      uD4cunMTUUKYYE1lpnYWzz3BYHIPerf1PZvwCDY60bUobH5X9Lnpk6JB0DbwRA3J
      LwLwujA9pWowUPTiU/lnssuuUYOuF12vGVsc8Qa1B50ufribQsA=
      -----END RSA PRIVATE KEY-----*/
    caCert: '-----BEGIN CERTIFICATE-----\r\n' +
      'MIIDEjCCAfqgAwIBAgIIJpO/C+XBou8wDQYJKoZIhvcNAQELBQAwHzELMAkGA1UE\r\n' +
      'BhMCVVMxEDAOBgNVBAMTB1Rlc3QgQ0EwHhcNMjQwNzMwMDAwMDAwWhcNMzQwNzI5\r\n' +
      'MjM1OTU5WjAfMQswCQYDVQQGEwJVUzEQMA4GA1UEAxMHVGVzdCBDQTCCASIwDQYJ\r\n' +
      'KoZIhvcNAQEBBQADggEPADCCAQoCggEBAKYGis5dDCF4xRspDSjj17mJ9BvZcCyd\r\n' +
      'nkU0XKalF4lqsEhAA38iv+alG3ne14CCD1/I/AoIZuI06g8lROurF+31k6qGOL4X\r\n' +
      'xJlRnYatkOJ4iOcS799jWuuis7TBlWgdhWG6rsFxjdkaKRwnMi0C9pK6YYpOBbZ/\r\n' +
      'gieqit/HMxNkl+CajEitpI376wQJClKAHiYKs1f+iAhtE9o+zFXmDfMoHnuWEL2g\r\n' +
      'Wh4Kvq3f54+52qlDaSqFgg+Pb2iEJ9AlMd/ZgjHQkP2Y09HXa9dG4yDdk2uyX+aO\r\n' +
      'l5yBmN/CJqQbbs4pKc3TBJF/tiY46PzEvjPdNPKWY5GwZAwsb8TD4HcCAwEAAaNS\r\n' +
      'MFAwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUhCDAEgZnoevZblFVw+RdSGsC\r\n' +
      'YK4wCwYDVR0PBAQDAgEGMBEGCWCGSAGG+EIBAQQEAwIABzANBgkqhkiG9w0BAQsF\r\n' +
      'AAOCAQEAfFS8ab8eYTMun6mH5AMqiJ+FLkx5IbZhteVFdXtGm+vC4kf1r9zsaKmv\r\n' +
      'CGfd7hoNBB4RPq9U7WyFAt2sfqJPkdd9OoJqkZmz1TlAhu7A7fZP/WtCy6FemN/r\r\n' +
      'ZbFFjlfnwBv86l/V1kvkHsZdR8AMwbU+CNObfvzMueCC4h+j7ybf/lEPf0hodqR4\r\n' +
      '2OAr/sy7EyzBMlD718q9W93e/35G8rNaYNP/LfO03oOcmYEoBSqGzuHhg+ZlEqM+\r\n' +
      'kfBn+nWGb7UniQJDFBVSGb8yad+NWGwaayZ0VpdPe5kBl8hRKBGEEwmMee1kti9m\r\n' +
      '7hhYWEVbfOf8rtL2W0rCDm7A6xROXQ==\r\n' +
      '-----END CERTIFICATE-----',
    crl: '-----BEGIN X509 CRL-----\r\n' +
      'MIIB3jCBxwIBATANBgkqhkiG9w0BAQsFADAfMQswCQYDVQQGEwJVUzEQMA4GA1UE\r\n' +
      'AxMHVGVzdCBDQRcNMjQwNzMwMDAwMDAwWhcNMjQwODI4MjM1OTU5WjBDMEECCDa4\r\n' +
      '2ilYjPkhFw0yNDA3MzAwODMwNTZaMCYwGAYDVR0YBBEYDzIwMjQwNzMwMDgzMDAw\r\n' +
      'WjAKBgNVHRUEAwoBBaAvMC0wHwYDVR0jBBgwFoAUhCDAEgZnoevZblFVw+RdSGsC\r\n' +
      'YK4wCgYDVR0UBAMCAQEwDQYJKoZIhvcNAQELBQADggEBAF63xKW9rKRaYRgiH0qA\r\n' +
      'ZmzlHm75JSxpi7Cym0xxJLjwezOX9bn3kv18uWRGsjZ1mSGYfqnVPTxbLU0pmvwo\r\n' +
      'dWCUiZD1/19MCUoMh6qA882jTU2KIU6ib3ooYphH68UcLI/OWwqGVYjBWZo+kgHL\r\n' +
      't8X7oRlhjJuTlOTTvITqUhFYUF4QpPUVf35qs7/lfpCR9XEfzRgJQuupuwwDh8mU\r\n' +
      'm0hc1EE+w7OnnkIjTHkAiIF97+ZTw9Q5ZwRz3i+N3FuPkLhzb4ZTIZuGLd+P/JfW\r\n' +
      'egZCmYxqAh8EqP97dfL8ONx3y8A8+oX1/YlQfkNFdRl0ycOWWMBI5weuXNpxnU+J\r\n' +
      'gwY=\r\n' +
      '-----END X509 CRL-----',
    nonRevokedCert: '-----BEGIN CERTIFICATE-----\r\n' +
      'MIIC/zCCAeegAwIBAgIIClyuSS0X1skwDQYJKoZIhvcNAQELBQAwHzELMAkGA1UE\r\n' +
      'BhMCVVMxEDAOBgNVBAMTB1Rlc3QgQ0EwHhcNMjQwNzMwMDgzMDAwWhcNMjUwNzMw\r\n' +
      'MDgzMDAwWjAvMQswCQYDVQQGEwJVUzEgMB4GA1UEAxMXVGVzdCBOb24gUmV2b2tl\r\n' +
      'ZCBDbGllbnQwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDQWBOO2fYu\r\n' +
      'gmcb/BkKVnVTgJg7+8QNj/KouIzDJ047ID6OiTrmM9kP9C+9oDr0ubmJNdGWQ90z\r\n' +
      'ymd7+obCHtW5m7ikQrT+huXM9hYnKbduBch0k+Sfh7qN8GfT1YJjuGRGcd/tXLeI\r\n' +
      'wDyhqC+/y6csEyJxyLPWX+iElCrAbQ//bWzT2M5oNHsraN6RiGDWSzs4l8Uj53pV\r\n' +
      'FURuamT3m5NqIlQPPl4Z3b9FT0S262aPM0yp+mDq9/nrdbvVOKDcj7fGTBLRNJgh\r\n' +
      'JydRJtRWQvSGQ76+FlpGIzULBM1bIYcZPJCFBpIcHi+qk0MGKyNuIc4ZNncfY90O\r\n' +
      'NN/rWG7Hu4P9AgMBAAGjLzAtMAwGA1UdEwEB/wQCMAAwHQYDVR0OBBYEFC/ruN0B\r\n' +
      '14D/YN/tEdVdnolMFgitMA0GCSqGSIb3DQEBCwUAA4IBAQCZ04mpam1fJuEv7JPX\r\n' +
      'w5TlHeYouZIFfQ+DeBNROi81QquPpdBmxXQftdRi7353+DGE2WaA09etZ8VOpzee\r\n' +
      '1aaCORAGj3R0pg7sgltC1YgPrv1m1MqWymhmruMVV6itIkj+vJTQwSVPC+3A8PDO\r\n' +
      '1JO7fwbb19MoCAWaKXTLioIRAHzzB+XvJTkfY/Bu62MNL2i07WFKAbg7b4/5RXmY\r\n' +
      'Uyr/g+rsIo8Qsp2y/WAD355KQ81kG+7D6PZXUlj3akXLp6s7G3Q6xRDTRtmD2GPJ\r\n' +
      'VcNNhZNAKojYk31CWXxZaEdT6EIvr46bXC/lzDRUCD1RNTFeB5WIUlWUfOhyQQDW\r\n' +
      '9CtR\r\n' +
      '-----END CERTIFICATE-----',
    /*nonRevokedCertKey: -----BEGIN RSA PRIVATE KEY-----
      MIIEowIBAAKCAQEA0FgTjtn2LoJnG/wZClZ1U4CYO/vEDY/yqLiMwydOOyA+jok6
      5jPZD/QvvaA69Lm5iTXRlkPdM8pne/qGwh7VuZu4pEK0/oblzPYWJym3bgXIdJPk
      n4e6jfBn09WCY7hkRnHf7Vy3iMA8oagvv8unLBMicciz1l/ohJQqwG0P/21s09jO
      aDR7K2jekYhg1ks7OJfFI+d6VRVEbmpk95uTaiJUDz5eGd2/RU9EtutmjzNMqfpg
      6vf563W71Tig3I+3xkwS0TSYIScnUSbUVkL0hkO+vhZaRiM1CwTNWyGHGTyQhQaS
      HB4vqpNDBisjbiHOGTZ3H2PdDjTf61hux7uD/QIDAQABAoIBABBlVgiwa3jGh2HC
      6Z+QJUSQgqp5yjh9Aw43E9DJ15S8mV+zOgDixKrGPzmPkgQvV4QOSbOnHJHWVGWD
      1jYRoiUstY+rtj2vlQcXuK+VT1untdpCx0OstUg1Sp53l37MhIusq4AtAz6OTlc0
      eql/1+SWjufgcRKmUpCYbnLdQlyJ9iI7g/75r0hYRvs9LV6xQYGftr+Eenm1n9XS
      vIni9m48BRL56QltJNgiXLNVG5Y8XrG0q8ZWCnsFdors+3ygpqm5HZikRAwfXwmJ
      6FRiipJA1s4XmHog6UQjcIIrAvwEIxMNv1vIfmdS7Xmnn+ezRU7tZBEerxw6JV7f
      gU232RECgYEA4d9CVZsgRfO3HFe+OwMsENO1rbVyvV0/LRURToBPnl5O9+oGP5KY
      MYlQcziEQa8vXjcqD6FkDcTY9CL51agMN6jUbWJWXIhbs9oLVDRn9+q3scXRes8T
      hD68Kffzr9rudxljM2jDl3mXUeWBfLd6guwiMoVBEhOg82oWHH/5rpkCgYEA7CJL
      qI1DJrKKp18iGR/Nxtqo15zBbUR4U2MMYai8C575sFQ5yAuE4FcmEGxR51VoX9B8
      As/UKUANzJDwH9Rve4es8J6Zs0agKP2AOCtxEJJYDbe/H8IK7kUwHEvmCLrDL+vO
      7iX/IUvYiUi24FmgRQlBr4S66szZlXEPFntr0wUCgYB/620qBlzUwR4nExpNWZKP
      RRdTdbuxuymYYqIWj1yIGGkoxoUbY+6Fv3qshomAmbJ97UgI6iI8Ggu02Eod0rp4
      m0kTWeoHJcKprQdVfQiUw32dVKc6oiQvdUgjjKWaJqd/FAW2i9KZ6ubkHtKiy1a6
      5vjHG+iqUCuLL72uDlxdoQKBgByC05HJZKdCfX1R/kL8VRNCiYpnEe/IiaK/3dnY
      zsO0cT96G/PseCHCRAVNnuIIrO6MtLx+LYbBhikCAwxE0SUgL6Bp9fLwfxwT56xg
      imlO0jTtz7Tc8Abu8a0o+OBq9HBPz49vpQt3JfEFh5c1GyXaxUSVCSCalVb27LRx
      OIalAoGBANWJsdC3ByPEmo9qx/SGThbe9uBIASstL+fmk6tJeyxtcD5UpxaQJHvd
      KEwnRNk+THcbbRjBg0O3M9c98Kdgy4PlVsQ68244H3XG20ZhdNmQ+JKDOclj8B6U
      OXxzGJChZlhs6p71o9WeN94OvbGwHjT8swY9Nk4OC+YEng4EqCJC
      -----END RSA PRIVATE KEY-----*/
    revokedCert: '-----BEGIN CERTIFICATE-----\r\n' +
      'MIIC+zCCAeOgAwIBAgIINrjaKViM+SEwDQYJKoZIhvcNAQELBQAwHzELMAkGA1UE\r\n' +
      'BhMCVVMxEDAOBgNVBAMTB1Rlc3QgQ0EwHhcNMjQwNzMwMDgyOTAwWhcNMjUwNzMw\r\n' +
      'MDgyOTAwWjArMQswCQYDVQQGEwJVUzEcMBoGA1UEAxMTVGVzdCBSZXZva2VkIENs\r\n' +
      'aWVudDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBANrhP9CWtKP7y82f\r\n' +
      'zbfGREVNcZ1qFcfLWXsZCAXItp2OKHHXFdgG3A0juAHuFGZXQ7cMHURhFxhU+bli\r\n' +
      'pZjBBxYxJInk775CRNKxV0oZ0HjgWMaI4Uneehi72qaOirXyQLKwKf8Go/4HLaF5\r\n' +
      '/wZdiG2RSnC4jyYbpkzJXKJEpvHvQVmOqvQBCFmMVlRXq7Ltcg2FLAi6JLe2oSUd\r\n' +
      'q+gG4GRojAdyhraDz1MvTrh7LnRq0TIGnQkF7rBhfDOKi9XiwsRlKmTuF+zbU8cJ\r\n' +
      '+pVPv3qnDNRUEyfir7V2t879B0fMW69inBEWTMgVIEJPWpf//NG+A8BxSIPkHOXS\r\n' +
      'y5f6lvMCAwEAAaMvMC0wDAYDVR0TAQH/BAIwADAdBgNVHQ4EFgQU/T+uLKWxnQYV\r\n' +
      '4FDRXZylBVLwXS4wDQYJKoZIhvcNAQELBQADggEBAI1dXV/7ptmVL+DyHBloUQdZ\r\n' +
      'qbenBCPX21cN4x/1FwoysV+yhY97mLAhLja/TGhLuz+W8y/NvVQQRWjdPEgyz9P5\r\n' +
      '1PJDkrcySSbjdlhYcIRQMjpPirXcBPouBQiuZ6hlqBARdLQ6pdW7COVec3L2jSDq\r\n' +
      '/7PGMAMiwTMwQ0i5mdASw6Z4RJwjvBWi2Bugw4Fy5EeBfp3bPfnsosXo+nKvCbMf\r\n' +
      '9lXmfE6wqWg8p/ha0auCD1nnCOifXX/ZaQ6sQcupZKxve0or6VB2P2uIfwWoz2eu\r\n' +
      'LbqS6Lh1K0VEwf6aq2mOpCfsrNHvBFbwwYescIwrRgFJpsxNqQhHq+f7oZ1iS70=\r\n' +
      '-----END CERTIFICATE-----'
    /*revokedCertKey: -----BEGIN RSA PRIVATE KEY-----
      MIIEpAIBAAKCAQEA2uE/0Ja0o/vLzZ/Nt8ZERU1xnWoVx8tZexkIBci2nY4ocdcV
      2AbcDSO4Ae4UZldDtwwdRGEXGFT5uWKlmMEHFjEkieTvvkJE0rFXShnQeOBYxojh
      Sd56GLvapo6KtfJAsrAp/waj/gctoXn/Bl2IbZFKcLiPJhumTMlcokSm8e9BWY6q
      9AEIWYxWVFersu1yDYUsCLokt7ahJR2r6AbgZGiMB3KGtoPPUy9OuHsudGrRMgad
      CQXusGF8M4qL1eLCxGUqZO4X7NtTxwn6lU+/eqcM1FQTJ+KvtXa3zv0HR8xbr2Kc
      ERZMyBUgQk9al//80b4DwHFIg+Qc5dLLl/qW8wIDAQABAoIBABmpJWrLoFXxTo1x
      hL6yNzggwjHVnsQTqmPs0AH4QWCWAAEzWX5AH6BIEGnkLZlp9ahfeow/uGNujZsX
      CO8FrP0EZJI+DYAIE5AtS7HboOiVn2gh4re0UNWBgJAyTz98LUBFuEa2fUIU5Aag
      X4Oxh4MWRjHnkUYYdmteLXFgtxR55BdeBnq7zV4ypqapb4RZgW96cuC6VctYeTCL
      pPwXwn56LtOfKjIAn8+bY2w8aw795TABdHHZ+1bMQirq/I71r/OY4W+DPq/99qX+
      fxIuJl3YiewB8ooA/d2jsiLBpL2214JoCYAO+5Bk53CT3nbX8LcNebQ4YcXDlGrK
      oGpEBSECgYEA9Vi26BN+hujzK3IoFzZcI3llohOElzLfIKhIKttmkMe2TGcVPLh9
      aGm7KFJJTo5U6zt/7z9paFBcSYyw2ZeUtmeIA9qrAAJwBTRQ52lz4ofAFILVzFqa
      k8Oh0GhsN8HKDmsjhknyi3iBp2u/lrL9Z15nPfS90tyMRA/jlxC9PesCgYEA5GJU
      d8A/a5Uo2skgjvDLT6gNPv7gLCZLz7VK9SnJ6vWAeJuzNqDh72aJh1NAtsIuMWDF
      CWpT0/AJsnIrCLJQIMzJnQ2mJ6U6PX46HeCg6jW7X9rtRt7Bo3b9DK41ZoBnMez9
      AXjvb1KgNJLs0sw1FnNJxnjjv/6MktqKw5084RkCgYAPuDJn5i/aJvzFkNfevN3k
      a/fGDagWI+1F42JUVKBasGEOviAPNubaFMQoDjWiMd5g//vvcUmopFV1ZO1D08F0
      emetj4obQwy4WKTCXvBM2FPHPKbEJB35T7SDbN1aKTFwAQ9SoFRI+VydRHsPBcLU
      p6jHwHGVHApkpfv4BtuJJwKBgQDOKx4JhJk760kYSJyFrUY8QH7EsZ14/ZFOjmB+
      dRz8aGdzeUsNM6sCTNQ2P6eZ1C2TEcKNv1ixaG24k2vZy+6dzYDrsFigTX4H6R1Z
      v2BETgE6hQ3R/mFbyZyih9lZEO0XmtLDM4MiQbqx+zijCwmZnLWq35LpzUblgzfl
      YtqEcQKBgQDsvhGMcEWtklbl/DPOzSiIBxpUQ6BWPEvEL63RFYIjA86sOgp0+zfC
      rUJodBGeGmCmSK6hugodL8X9XbHDvvvtfnyF9uLLExR6e5qI39ofmt3KEaKjpYhQ
      0c7g51j4JmQsBgbUSHEMAhFV49WmEapOOqkZces+jSMYxEDOzlOl/Q==
      -----END RSA PRIVATE KEY-----*/
  };

  describe('crl', function() {
    it('should be able to read a PEM encoded CRL', function() {
      PKI.certificateRevocationListFromPem(_pem.crl);
    });

    it('should be able to read a CRL\'s properties', function() {
      var crl = PKI.certificateRevocationListFromPem(_pem.crl);
      ASSERT.equal(crl.version, 0x01);
      
      ASSERT.notEqual(crl.signature, undefined);
      ASSERT.notEqual(crl.signature, null);
      ASSERT.equal(crl.signatureOid, PKI.oids.sha256WithRSAEncryption);
      ASSERT.notEqual(crl.signatureParameters, undefined);

      ASSERT.equal(crl.siginfo.algorithmOid, PKI.oids.sha256WithRSAEncryption);
      ASSERT.notEqual(crl.siginfo.signatureParameters, undefined);

      ASSERT.notEqual(crl.tbsCertList, undefined);

      ASSERT.notEqual(crl.issuer.attributes, undefined);
      ASSERT.notEqual(crl.issuer.attributes, null);
      ASSERT.equal(crl.issuer.hash, '4c7be0031d89818ef4e069d62ae9e500ec2c5812');

      ASSERT.equal(crl.thisUpdate.toUTCString(), 'Tue, 30 Jul 2024 00:00:00 GMT');
      ASSERT.equal(crl.nextUpdate.toUTCString(), 'Wed, 28 Aug 2024 23:59:59 GMT');

      ASSERT.notEqual(crl.revocations.length, 0);
      ASSERT.notEqual(crl.extensions.length, 0);
    });

    it('should be able to create a digest for a CRL', function() {
      var crl = PKI.certificateRevocationListFromPem(_pem.crl, true);
      ASSERT.notEqual(crl.md, undefined);
      ASSERT.notEqual(crl.md, null);
    });

    it('should be able to identify a Delta CRL', function() {
      var crl = PKI.certificateRevocationListFromPem(_pem.crl);
      
      ASSERT.equal(crl.isDelta(), false);
      //TODO: Add delta CRL
    })

    it('should be able to read a CRL\'s extensions', function() {
      var crl = PKI.certificateRevocationListFromPem(_pem.crl);
      ASSERT.equal(crl.version, 0x01);

      ASSERT.equal(crl.getExtension({id: PKI.oids.cRLNumber}).number, 1);
      ASSERT.equal(crl.getExtension({id: PKI.oids.authorityKeyIdentifier}).authorityKeyIdentifier, '8420c0120667a1ebd96e5155c3e45d486b0260ae');
      //TODO: Test more extensions when added
    });

    it('should be able to verify the CRL\'s signer', function() {
      var crl = PKI.certificateRevocationListFromPem(_pem.crl, true);
      var ca = PKI.certificateFromPem(_pem.caCert);
      var nrClient = PKI.certificateFromPem(_pem.nonRevokedCert);

      ASSERT.equal(crl.verify(ca), true);
      ASSERT.equal(crl.verify(nrClient), false);
    });

    it('should be able to identify revoked certificates', function() {
      var crl = PKI.certificateRevocationListFromPem(_pem.crl);
      var rClient = PKI.certificateFromPem(_pem.revokedCert);
      var nrClient = PKI.certificateFromPem(_pem.nonRevokedCert);

      ASSERT.equal(crl.isCertRevoked(rClient), true);
      ASSERT.equal(crl.isCertRevoked(nrClient), false);
    });

    it('should be able to read a CRL\'s revocation entry & its extensions', function() {
      var crl = PKI.certificateRevocationListFromPem(_pem.crl);
      var rClient = PKI.certificateFromPem(_pem.revokedCert);

      var revocationEntry = crl.getRevocation(rClient.serialNumber);
      ASSERT.notEqual(revocationEntry, null);

      ASSERT.equal(revocationEntry.getExtension({id: PKI.oids.invalidityDate}).invalidSince.toUTCString(), 'Tue, 30 Jul 2024 08:30:00 GMT');
      ASSERT.equal(revocationEntry.getExtension({id: PKI.oids.cRLReason}).reason, 5);
      //TODO: Add certificateIssuer when added
    });
  });

})();
