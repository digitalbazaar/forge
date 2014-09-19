# 0.7.0-dev (2014-09-17)

## Breaking Changes

- **start(En|De)crypting**, **create(En|De)cryptionCipher** deprecated APIs
  replaced by **forge.cipher** API
- **pbe.getCipher**, **pbe.getCipherForPBES2**, **pbe.getCipherForPKCS12PBE**
  changed to **pbe.getDecipher**, **pbe.getDecipherForPBES2**, **pbe.getDecipherForPKCS12PBE**
- **tls.connected** is now called prior to flushing the final finished record;
  it used to be called afterwards, but that could trigger **tls.dataReady**
  to be called first in a synchronous environment.
- **captureAsn1** has been replaced with ```capture: {name: '<foo>', format: 'asn1'}```
  Multiple captures of the same value (but in different formats) can be
  obtained by specifying 'capture' as an array.
- Parsed ASN.1 objects now use native JavaScript primitives for OIDs,
  strings, and integers. Different formats can be used via the ASN.1 validator
  capture API. When capturing ASN.1 values, ASN.1 INTEGERS may be captured
  as 'number', 'hex', or 'buffer'. UTCTIME and GENERALIZEDTIME can be captured
  as Dates by specifying 'date'. A BITSTRING can be captured as a 'buffer' to
  prevent auto-matic composition detection.