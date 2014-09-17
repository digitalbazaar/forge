# 0.7.0-dev (2014-09-17)

## Breaking Changes

- **start(En|De)crypting**, **create(En|De)cryptionCipher** deprecated APIs
  replaced by **forge.cipher** API
- **pbe.getCipher**, **pbe.getCipherForPBES2**, **pbe.getCipherForPKCS12PBE**
  changed to **pbe.getDecipher**, **pbe.getDecipherForPBES2**, **pbe.getDecipherForPKCS12PBE**
- **tls.connected** is now called prior to flushing the final finished record;
  it used to be called afterwards, but that could trigger **tls.dataReady**
  to be called first in a synchronous environment.
