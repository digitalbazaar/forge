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
- Parsed ASN.1 objects now use native JavaScript primitives for certain
  types in the UNIVERSAL class, including strings, times, BOOLEAN, INTEGER,
  NULL, and OIDs. Different formats can be used via the ASN.1 validator
  capture API. When capturing ASN.1 values, ASN.1 INTEGERS may be captured
  as 'number', 'hex', or 'buffer'. UTCTIME and GENERALIZEDTIME can be captured
  as Dates by specifying 'date'. A BITSTRING can be captured as a 'buffer' to
  prevent automatic composition detection.
- All message digest **update** calls accept ByteBuffers or strings, but
  if a string is given, the encoding must also be given, there is no default.
- The string encoding **raw** has been replaced with **binary**. This does not
  affect the actual encoding, rather it only refers to the name passed to
  functions to indicate the encoding. Previously "raw" was deprecated in
  preference to "binary" which is in common usage in node.js. Now "raw"
  will be considered an unrecognized encoding.
- **hmac.getMac** has been removed, replaced with its previous alias **hmac.digest**.
- **pki.rsa.encrypt** and **pki.rsa.decrypt** have been removed, use
  **publicKey.encrypt**, **publicKey.verify**, **privateKey.decrypt** or
  **privateKey.sign** on a public or private key object.
- Using a 'NONE' or null signature scheme when generating an RSA signature
  will now use raw RSA encryption; previously EME-PKCS1-v1_5 (PKCS#1 v1.5
  padding block type 2) was applied. To apply this padding use: 'EME-PKCS1-v1_5'
  instead.
- PKCS#1 v1.5 functions have been moved to pkcs1.js and this introduced a
  dependency on asn1.js.