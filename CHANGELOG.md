Forge ChangeLog
===============

## 1.4.2 - 2026-10-27

### Fixed
- [pem] Convert non-string input to a string in `pem.decode()` as before
  1.4.1. The 1.4.1 PEM ReDoS fix (GHSA-7wch-p9px-956x) caused a `TypeError`
  for `Buffer` input, which is used by `node-jose`.
  ([#1165](https://github.com/digitalbazaar/forge/issues/1165))

## 1.4.1 - 2026-10-27

### Notes
- This release involved coordinating many security reports from many groups,
  people, and robots over too long period of time. Thank you for your reports
  and patience.
- Claude Code was used to help organize, track, untangle, merge, test,
  validate, fix, and improve it all. Further verification of fixes would be
  welcome.
- Tracking credits was challenging for some issues due to multiple email and
  GitHub reports, incomplete contact details, or combining of partial reports
  and fixes. Please let us know if there are credits changes needed here or in
  advisory data.

### Security
- **HIGH**: Signature forgery in RSA-PKCS due to ASN.1 extra field in
  DigestAlgorithm.
  - RSASSA PKCS#1 v1.5 signature verification accepts forged signatures for low
    public exponent keys (e=3). The fix for CVE-2026-33894 only checked the
    element count of the outer DigestInfo. Attackers can add "garbage" elements
    inside the nested DigestAlgorithm SEQUENCE in order to construct a
    signature that passes verification, enabling Bleichenbacher style forgery.
  - Reported by Geo (@geo-chen).
  - CVE ID: [CVE-2026-85393](https://www.cve.org/CVERecord?id=CVE-2026-85393)
  - GHSA ID: [GHSA-2g46-22mc-6gwp](https://github.com/digitalbazaar/forge/security/advisories/GHSA-2g46-22mc-6gwp)
- **HIGH**: Signature forgery in RSA-PKCS due to non-canonical DigestInfo
  encoding.
  - RSASSA PKCS#1 v1.5 signature verification accepts non-canonical DigestInfo
    encodings, such as NULL parameters with content, non-minimal length
    encodings, and non-canonical OIDs. These provide attackers space to
    construct forged signatures for low public exponent keys (e=3), similar to
    CVE-2026-33894 and CVE-2026-85393.
  - Reported by Oren Yomtov (@orenyomtov, Fireblocks), Bronson Yen (Calif.io,
    in collaboration with Claude and Anthropic Research), Kamil Hałajda,
    @pzartech, @antonlissone, and @Brechard.
  - CVE ID: [CVE-2026-119192](https://www.cve.org/CVERecord?id=CVE-2026-119192)
  - GHSA ID: [GHSA-6qrw-m8cv-hcxf](https://github.com/digitalbazaar/forge/security/advisories/GHSA-6qrw-m8cv-hcxf)
- **HIGH**: ASN.1 resource exhaustion via BIT STRING decoding.
  - An Uncontrolled Recursion (CWE-674) and Uncontrolled Resource Consumption
    (CWE-400) vulnerability in node-forge versions 1.4.0 and below enables
    remote, unauthenticated attackers to exhaust CPU and memory with small
    crafted DER or PEM inputs (certificates, keys, and other structures parsed
    with `asn1.fromDer()`). By default `fromDer()` attempts to decode BIT
    STRING contents as ASN.1. That decode ignored the global `asn1.maxDepth`
    and the per-call `maxDepth` option, and BIT STRINGs nested in decoded BIT
    STRINGs were decoded too, with each level keeping a full copy of its
    decoded contents. Memory use grew quadratically with the nesting depth
    and can terminate the process from heap exhaustion. The `maxDepth` bypass
    is an incomplete fix of CVE-2025-66031.
  - Reported by:
    - Ethan Kim (cremit.io).
    - Youngjoon Kim (@acorn421) and Brian Lee (@hibrian827), Georgia Tech
      SSLab.
    - @arpitjain099.
    - Mike Read.
  - CVE ID: [CVE-2026-119191](https://www.cve.org/CVERecord?id=CVE-2026-119191)
  - GHSA ID: [GHSA-rhr8-3pm8-cq29](https://github.com/digitalbazaar/forge/security/advisories/GHSA-rhr8-3pm8-cq29)
- **HIGH**: Regular expression denial of service in PEM decoding.
  - An Inefficient Regular Expression Complexity (CWE-1333) vulnerability in
    node-forge versions 1.4.0 and below enables remote, unauthenticated
    attackers to block the event loop with small crafted inputs to
    `pem.decode()` and the APIs that parse PEM, such as
    `pki.certificateFromPem()` and `pki.privateKeyFromPem()`. The regular
    expression that splits PEM messages takes polynomial time on input
    without a matching END line; a 30 KB input took over 20 seconds. The
    regular expressions that parse encapsulated headers took quadratic time
    on long header lines.
  - Reported by:
    - Ahmed Mokhtari (@AhmedMokhtari), @mwlik, and @imenyoo2.
    - @offset.
    - @bibu123456.
    - @Mucahic.
  - CVE ID: [CVE-2026-118779](https://www.cve.org/CVERecord?id=CVE-2026-118779)
  - GHSA ID: [GHSA-7wch-p9px-956x](https://github.com/digitalbazaar/forge/security/advisories/GHSA-7wch-p9px-956x)
- **HIGH**: Denial of service in TLS record processing via call stack
  exhaustion.
  - `tls.createConnection()` connections handle received records recursively:
    each record handler calls `process()` again for the next buffered record.
    A peer can send one chunk of many small records, such as heartbeat
    records, which are accepted in every state including before the
    handshake, and `process()` throws `RangeError: Maximum call stack size
    exceeded`. In Node.js applications that call `process()` from a socket
    `data` handler, the exception is uncaught and terminates the process.
    Server and client connections are affected, and no authentication is
    required.
  - Reported by:
    - Ziyue Wang, Chenchen, Strick Sheng, Liyi Zhou, and Maurice Ng.
  - CVE ID: [CVE-2026-119187](https://www.cve.org/CVERecord?id=CVE-2026-119187)
  - GHSA ID: [GHSA-hqq3-7jhf-c5jx](https://github.com/digitalbazaar/forge/security/advisories/GHSA-hqq3-7jhf-c5jx)
- **HIGH**: Denial of service in TLS record processing via an interleaved
  record during a fragmented handshake message.
  - When a `tls.createConnection()` connection receives a record of another
    type (alert, change_cipher_spec, application data or heartbeat) while a
    handshake message is split across records, it reports the error and
    closes the connection, and then `process()` throws `TypeError: Cannot
    set properties of null`. A peer can trigger this with two small records
    before the handshake, without authentication, as a server or a client.
    In Node.js applications that call `process()` from a socket `data`
    handler, the exception is uncaught and terminates the process.
  - CVE ID: [CVE-2026-119188](https://www.cve.org/CVERecord?id=CVE-2026-119188)
  - GHSA ID: [GHSA-8hrf-8g6f-7xwp](https://github.com/digitalbazaar/forge/security/advisories/GHSA-8hrf-8g6f-7xwp)
- **HIGH**: PKCS#12 MAC forgery due to missing iteration count check.
  - `pkcs12.pkcs12FromAsn1()` accepts a PKCS#12 MAC iteration count of zero
    from the input. With fewer than one iteration, the PKCS#12 key derivation
    function (RFC 7292 Appendix B.2) does no hashing and returns a constant key
    that does not depend on the password or salt. An attacker who does not know
    the password can modify the contents of a PKCS#12/PFX file, such as
    replacing certificates or keys, and compute a MAC that verifies with any
    password. The PKCS#12 password-based encryption schemes
    (`pbeWithSHAAnd3-KeyTripleDES-CBC`, `pbewithSHAAnd40BitRC2-CBC`) are
    affected the same way: with zero iterations they use a constant key and
    IV, so a substituted encrypted private key decrypts with any password.
  - Reported by Thai (Calif.io), in collaboration with Claude and Anthropic
    Research.
  - CVE ID: [CVE-2026-118782](https://www.cve.org/CVERecord?id=CVE-2026-118782)
  - GHSA ID: [GHSA-jc66-7q78-782g](https://github.com/digitalbazaar/forge/security/advisories/GHSA-jc66-7q78-782g)
- **HIGH**: `basicConstraints` bypass via deprecated extension OIDs in
  certificate chain verification.
  - node-forge parses extensions with the deprecated OIDs `2.5.29.10` and
    `2.5.29.13` as `basicConstraints`, and `pki.verifyCertificateChain()`
    used the first extension with that name. A certificate with a forged
    deprecated-OID extension (`cA` TRUE) before its genuine `basicConstraints`
    extension (`cA` FALSE) is accepted as a CA, and the same technique can
    hide a `pathLenConstraint`. An attacker who obtains such a certificate
    from a trusted CA that copies extensions from certificate requests can
    issue certificates for any name that node-forge accepts as valid.
  - Reported by @nickcollisson-workos (WorkOS Security Team).
  - CVE ID: [CVE-2026-119190](https://www.cve.org/CVERecord?id=CVE-2026-119190)
  - GHSA ID: [GHSA-5x38-2vff-x55p](https://github.com/digitalbazaar/forge/security/advisories/GHSA-5x38-2vff-x55p)
- **MODERATE**: Denial of service in the TLS client when the server sends no
  certificate.
  - A NULL Pointer Dereference (CWE-476) vulnerability in node-forge versions
    1.4.0 and below lets a malicious TLS server, or an on-path attacker who
    removes the server's Certificate message, crash applications that use the
    forge TLS client. The client's check for a missing server certificate
    read the wrong property and never ran, so the handshake continued and
    `connection.process()` threw a `TypeError` instead of failing the
    connection.
  - Reported by @arpitjain099.
  - CVE ID: [CVE-2026-118778](https://www.cve.org/CVERecord?id=CVE-2026-118778)
  - GHSA ID: [GHSA-525v-9gp9-w22h](https://github.com/digitalbazaar/forge/security/advisories/GHSA-525v-9gp9-w22h)
- **MODERATE**: `pathLenConstraint` bypass in certificate chain verification.
  - `pki.verifyCertificateChain()` only enforces the `basicConstraints`
    `pathLenConstraint` of a CA certificate when that certificate also has a
    `keyUsage` extension. When a CA certificate with a `pathLenConstraint`
    lacks `keyUsage`, chains with more intermediate CA certificates below it
    than the constraint allows are accepted. The holder of such a constrained
    CA's key, or anyone it issues a CA certificate to, can create subordinate
    CAs whose certificates node-forge accepts as valid.
  - Reported by @offset, @eddieran, Zion Boggan (@zionboggan), and
    @EchoSkorJjj.
  - CVE ID: [CVE-2026-119189](https://www.cve.org/CVERecord?id=CVE-2026-119189)
  - GHSA ID: [GHSA-h46v-rmh6-fq4f](https://github.com/digitalbazaar/forge/security/advisories/GHSA-h46v-rmh6-fq4f)
- **MODERATE**: AES-GCM authentication bypass with an invalid tag length.
  - GCM mode does not validate the `tagLength` option. With a `tagLength` of
    `0` (or `null`, `false`, `''`, or `'0'`), the computed authentication tag is
    empty, and decryption with an empty or missing `tag` succeeds:
    `decipher.finish()` returns `true` for any ciphertext and additional data.
    An attacker can then forge or modify messages that the application accepts
    as authentic. This requires the application to pass such a `tagLength`,
    for example one derived from the length of a received tag. The default
    tag length of 128 bits is not affected.
  - CVE ID: [CVE-2026-119186](https://www.cve.org/CVERecord?id=CVE-2026-119186)
  - GHSA ID: [GHSA-5cwg-6vw7-rj6p](https://github.com/digitalbazaar/forge/security/advisories/GHSA-5cwg-6vw7-rj6p)
- **MODERATE**: Prototype pollution via `Set-Cookie` in `forge.http`.
  - A Prototype Pollution (CWE-1321) vulnerability in node-forge versions
    1.4.0 and below lets a malicious server add properties to
    `Object.prototype` and `Object`, or delete `Object.prototype`
    properties, in applications that use the `forge.http` client (included
    in the `forge.all` browser bundle, not loaded by `require('node-forge')`).
    Cookie names and paths from `Set-Cookie` headers were used as keys of a
    plain object with `in` checks, so `__proto__` and inherited names
    reached `Object.prototype`.
  - Reported by @arunmozhivarman-dtx and @Dremig.
  - CVE ID: [CVE-2026-118777](https://www.cve.org/CVERecord?id=CVE-2026-118777)
  - GHSA ID: [GHSA-6wvx-3r32-xmcg](https://github.com/digitalbazaar/forge/security/advisories/GHSA-6wvx-3r32-xmcg)
- **LOW**: ASN.1 OID first arc truncation.
  - An Integer Overflow (CWE-190) vulnerability in node-forge versions 1.4.0
    and below lets `asn1.oidToDer()` encode an OID string with out of range
    first arcs as a different OID, e.g. `0.42.840.113549.1.1.1` or
    `4294977127.18.840.113549.1.1.1` as rsaEncryption
    (`1.2.840.113549.1.1.1`), which can bypass OID-based decisions made on
    the string. The fix for CVE-2025-66030 only checked the later arcs.
  - Reported by wzc.
  - CVE ID: [CVE-2026-118775](https://www.cve.org/CVERecord?id=CVE-2026-118775)
  - GHSA ID: [GHSA-4642-5mcj-2rqw](https://github.com/digitalbazaar/forge/security/advisories/GHSA-4642-5mcj-2rqw)
- **LOW**: Certificate signature verified with the issuer's signature scheme.
  - An Improper Verification of Cryptographic Signature (CWE-347)
    vulnerability in node-forge versions 1.4.0 and below lets a certificate
    labeled as signed with RSASSA-PSS pass chain verification with a PKCS#1
    v1.5 signature. `certificate.verify(child)` and `verifyCertificateChain()`
    chose the RSA padding scheme and PSS parameters from the issuer
    certificate instead of the child certificate. The signature must still
    be made with the issuer's key, so this only misleads applications that
    rely on a certificate's signature algorithm.
  - Reported by Brian Lee (@hibrian827, Georgia Tech SSLab, Team Atlanta).
  - CVE ID: [CVE-2026-118774](https://www.cve.org/CVERecord?id=CVE-2026-118774)
  - GHSA ID: [GHSA-9wg5-mj3p-v49q](https://github.com/digitalbazaar/forge/security/advisories/GHSA-9wg5-mj3p-v49q)
- **LOW**: Incomplete PKCS#7 padding validation in CBC and ECB decryption.
  - An Improper Validation of Integrity Check Value (CWE-354) vulnerability in
    node-forge versions 1.4.0 and below makes `decipher.finish()` accept
    malformed padding in CBC and ECB mode. Only the last byte was checked,
    against a limit of four blocks, so mismatched padding bytes, a zero count
    and counts larger than a block were accepted, and up to four blocks of
    plaintext could be removed. CBC and ECB without a MAC never provide
    integrity, and this fix doesn't change that; use AES-GCM or authenticate
    the ciphertext.
  - Reported by Oren Yomtov (@orenyomtov, Fireblocks), @zebbern, and Brian Lee
    (@hibrian827, Georgia Tech SSLab, Team Atlanta).
  - CVE ID: [CVE-2026-118776](https://www.cve.org/CVERecord?id=CVE-2026-118776)
  - GHSA ID: [GHSA-2vgq-wchc-25w7](https://github.com/digitalbazaar/forge/security/advisories/GHSA-2vgq-wchc-25w7)
- **LOW**: Certificate chain verification removes trusted certificates from
  the CA store.
  - When a CA store created with `pki.createCaStore()` holds two or more
    certificates with the same subject name, `pki.verifyCertificateChain()`
    permanently removes certificates with that subject from the store while
    looking for the issuer of a certificate. A peer that sends a certificate
    naming that subject as its issuer, even one with an invalid signature,
    makes all later verifications of chains issued by those CA certificates
    fail, for as long as the store is in use. Verifying valid chains has the
    same effect. Verification never incorrectly succeeds because of this.
  - Reported by @pravichandran15.
  - CVE ID: [CVE-2026-118780](https://www.cve.org/CVERecord?id=CVE-2026-118780)
  - GHSA ID: [GHSA-4487-j8r4-4g2f](https://github.com/digitalbazaar/forge/security/advisories/GHSA-4487-j8r4-4g2f)
- **LOW**: Denial of Service in `BigInteger.modInverse()` with negative inputs.
  - The 1.4.0 fix for CVE-2026-33891 only handled a zero input.
    `BigInteger.modInverse()` still enters an infinite loop when the value or
    the modulus is negative, causing the process to hang indefinitely and
    consume 100% CPU. In forge this is reachable when a negative public
    exponent `e` is passed to `pki.rsa.generateKeyPair()` or
    `pki.rsa.createKeyPairGenerationState()`. Keys parsed from DER, PEM or JWK
    cannot produce negative values. Applications are affected only if they
    pass untrusted values as the RSA key generation exponent or call
    `modInverse()` with negative values.
  - Reported by wzc.
  - CVE ID: [CVE-2026-118781](https://www.cve.org/CVERecord?id=CVE-2026-118781)
  - GHSA ID: [GHSA-h6cr-wjv9-3cpp](https://github.com/digitalbazaar/forge/security/advisories/GHSA-h6cr-wjv9-3cpp)

### Fixed
- [rsa] Require a canonical DER DigestInfo in RSASSA PKCS#1 v1.5 signature
  verification by re-encoding the expected DigestInfo and comparing bytes, as
  in RFC 8017 8.2.2. Based on work in PRs by @matthewscottconroy (#1159),
  @shaswata56 (#1160), @nitrog7 (#1161), and @RoastFried-RF (#1162).
- [asn1] Apply the `fromDer()` `maxDepth` recursion limit when decoding ASN.1
  from BIT STRING contents. Contents that would exceed the limit are kept as
  an undecoded BIT STRING value.
- [asn1] Only decode one level of BIT STRING contents in `fromDer()`. BIT
  STRINGs inside decoded BIT STRING contents are kept as undecoded BIT STRING
  values. Their bytes are unchanged by `toDer()`.
  - **NOTE**: Code that relied on nested BIT STRING decoding needs to decode
    the inner BIT STRING value (after its leading unused bits octet) with
    `asn1.fromDer()`. Common structures such as SubjectPublicKeyInfo only use
    one level.
- [pem] Find PEM messages and parse encapsulated headers in linear time.
  Messages are matched as before, except that a BEGIN line's label is the
  shortest one followed by `-----` (RFC 7468 labels can't contain `--`).
- [asn1] Reject OIDs whose first arc isn't 0, 1 or 2, or whose second arc is
  over 39 under 0 or 1, in `asn1.oidToDer()`.
- [asn1] Encode and decode a multi-byte first OID subidentifier (e.g.
  `2.999`) in base 128. From PR #1148 by @spokodev.
- [tls] Process received TLS records in a loop instead of recursively, so the
  number of records in one `process()` call no longer affects stack depth.
- [tls] Stop processing a record that interrupts a fragmented handshake
  message after failing the connection with an `unexpected_message` alert,
  instead of throwing a `TypeError`.
- [tls] Fail the TLS client handshake with an `insufficient_security` alert
  when the server sends no certificate, even if the `verify` callback
  accepts it, since the RSA key exchange needs the server certificate.
- [pkcs12] Reject PKCS#12 MAC iteration counts less than one.
- [pbe] Reject iteration counts less than one in the PKCS#12 key derivation
  function `pbe.generatePkcs12Key()` (also `pkcs12.generateKey()`), used for
  PKCS#12 MACs and PKCS#12 password-based encryption.
- [x509] Use only the RFC 5280 `basicConstraints` OID (`2.5.29.19`) in
  certificate chain verification, not the deprecated OIDs that are also
  parsed as `basicConstraints`.
- [x509] Enforce `basicConstraints` `pathLenConstraint` in chain verification
  for CA certificates without a `keyUsage` extension.
- [x509] Verify a certificate's signature with the padding scheme and
  parameters of its own signature algorithm, using the issuer's public key.
  PKCS#1 v1.5 certificates issued by an RSASSA-PSS certificate, and the
  reverse, failed verification before.
- [cipher] Validate the GCM `tagLength` option. Only the tag lengths defined by
  NIST SP 800-38D (128, 120, 112, 104, 96, 64, and 32 bits) are allowed;
  numeric strings such as `'128'` are still accepted. A `null` or `undefined`
  `tagLength` uses the default of 128 bits.
  - **NOTE**: Zero and other invalid tag lengths (such as `0`, `false`, `''`,
    `8`, or `256`), which produced empty or non-conformant tags, now throw an
    error. A `null` or `undefined` `tagLength`, which produced an empty tag
    when encrypting, now means the default of 128 bits. Data previously
    encrypted with an empty tag can no longer be decrypted, since accepting
    an empty tag is the authentication bypass.
- [cipher] Require valid PKCS#7 padding when decrypting in CBC and ECB mode:
  a count from 1 to the block size, and every padding byte equal to the
  count.
  - **NOTE**: Data with other padding, such as ANSI X.923, ISO 10126 or
    XML Encryption padding, used to decrypt because only the last byte was
    checked, and now fails. To decrypt it, set `decipher.mode.unpad = false`
    before `finish()` and remove the padding in your code.
- [http] Only use own properties of the cookie store, and ignore cookies
  named `__proto__` or with the path `__proto__`.
- [x509] Do not modify the CA store's list of certificates with the same
  subject when trying each of them as the issuer in
  `pki.verifyCertificateChain()`.
- [jsbn] Fix `BigInteger.modInverse` to also exit early with zero when the
  target object value or the modulus is negative, completing the 1.4.0 fix
  that only checked for zero.
- [tls] Ignore heartbeat requests received before the first handshake is
  complete, instead of answering them. Previously, unauthenticated peers
  could make a connection create and send a heartbeat response for every
  request before the handshake, at a significant CPU cost per request.

## 1.4.0 - 2026-03-24

### Security
- **HIGH**: Denial of Service in `BigInteger.modInverse()`
  - A Denial of Service (DoS) vulnerability exists due to an infinite loop in
    the `BigInteger.modInverse()` function (inherited from the bundled jsbn
    library). When `modInverse()` is called with a zero value as input, the
    internal Extended Euclidean Algorithm enters an unreachable exit condition,
    causing the process to hang indefinitely and consume 100% CPU.
  - Reported by Kr0emer.
  - CVE ID: [CVE-2026-33891](https://www.cve.org/CVERecord?id=CVE-2026-33891)
  - GHSA ID: [GHSA-5gfm-wpxj-wjgq](https://github.com/digitalbazaar/forge/security/advisories/GHSA-5m6q-g25r-mvwx)
- **HIGH**: Signature forgery in RSA-PKCS due to ASN.1 extra field.
  - RSASSA PKCS#1 v1.5 signature verification accepts forged signatures for low
    public exponent keys (e=3). Attackers can forge signatures by stuffing
    "garbage" bytes within the ASN.1 structure in order to construct a
    signature that passes verification, enabling Bleichenbacher style forgery.
    This issue is similar to CVE-2022-24771, but adds bytes in an addition
    field within the ASN.1 structure, rather than outside of it.
  - Additionally, forge does not validate that signatures include a minimum of
    8 bytes of padding as defined by the specification, providing attackers
    additional space to construct Bleichenbacher forgeries.
  - Reported as part of a U.C. Berkeley security research project by:
    - Austin Chu, Sohee Kim, and Corban Villa.
  - CVE ID: [CVE-2026-33894](https://www.cve.org/CVERecord?id=CVE-2026-33894)
  - GHSA ID: [GHSA-ppp5-5v6c-4jwp](https://github.com/digitalbazaar/forge/security/advisories/GHSA-ppp5-5v6c-4jwp)
- **HIGH**: Signature forgery in Ed25519 due to missing S < L check.
  - Ed25519 signature verification accepts forged non-canonical signatures
    where the scalar S is not reduced modulo the group order (S >= L). A valid
    signature and its S + L variant both verify in forge, while Node.js
    crypto.verify (OpenSSL-backed) rejects the S + L variant, as defined by the
    specification. This class of signature malleability has been exploited in
    practice to bypass authentication and authorization logic (see
    CVE-2026-25793, CVE-2022-35961). Applications relying on signature
    uniqueness (i.e., dedup by signature bytes, replay tracking, signed-object
    canonicalization checks) may be bypassed.
  - Reported by:
    - Oren Yomtov (@orenyomtov, Fireblocks).
    - Austin Chu, Sohee Kim, and Corban Villa, as part of a U.C. Berkeley
      security research project.
  - CVE ID: [CVE-2026-33895](https://www.cve.org/CVERecord?id=CVE-2026-33895)
  - GHSA ID: [GHSA-q67f-28xg-22rw](https://github.com/digitalbazaar/forge/security/advisories/GHSA-q67f-28xg-22rw)
- **HIGH**: `basicConstraints` bypass in certificate chain verification.
  - `pki.verifyCertificateChain()` does not enforce RFC 5280 `basicConstraints`
    requirements when an intermediate certificate lacks both the
    `basicConstraints` and `keyUsage` extensions. This allows any leaf
    certificate (without these extensions) to act as a CA and sign other
    certificates, which node-forge will accept as valid.
  - Reported by Doruk Tan Ozturk (@peaktwilight) - doruk.ch
  - CVE ID: [CVE-2026-33896](https://www.cve.org/CVERecord?id=CVE-2026-33896)
  - GHSA ID: [GHSA-2328-f5f3-gj25](https://github.com/digitalbazaar/forge/security/advisories/GHSA-2328-f5f3-gj25)

### Added
- [oid] Added requested OID:
  - `2.5.4.65` / `pseudonym`

### Changed
- [jsbn] Update to `jsbn` 1.4. Sync partly back to original style for easier
  updates every decade or so.

### Fixed
- [jsbn] Fix `BigInteger.modInverse` to avoid an infinite loop and exit early
  with zero when the target object value is <= 0. Zero may not be strictly
  mathematically correct but aligns with current `jsbn` behavior returning zero
  in other situations. The alternate of a `RangeError` would diverge from the
  rest of the API.
- [rsa] Fix padding length check according to RFC 2313 8.1 note 6. Padding is
  required to be eight octets for block types 1 and 2.
- [rsa] Fix RFC 8017 DigestInfo parsing to require a sequence length of two.
- [ed25519] Add canonical signature scaler check for S < L.
- [x590] Add chain verification check for absent `basicConstraints` on non-leaf
  certificates.

## 1.3.3 - 2025-12-02

### Fixed
- [pkcs12] Make digestAlgorithm parameters optional to fix PKCS#12/PFX issues
  introduced in 1.3.2.

## 1.3.2 - 2025-11-25

### Security
- **HIGH**: ASN.1 Validator Desynchronization
  - An Interpretation Conflict (CWE-436) vulnerability in node-forge versions
    1.3.1 and below enables remote, unauthenticated attackers to craft ASN.1
    structures to desynchronize schema validations, yielding a semantic
    divergence that may bypass downstream cryptographic verifications and
    security decisions.
  - Reported by Hunter Wodzenski.
  - CVE ID: [CVE-2025-12816](https://www.cve.org/CVERecord?id=CVE-2025-12816)
  - GHSA ID: [GHSA-5gfm-wpxj-wjgq](https://github.com/digitalbazaar/forge/security/advisories/GHSA-5gfm-wpxj-wjgq)
- **HIGH**: ASN.1 Unbounded Recursion
  - An Uncontrolled Recursion (CWE-674) vulnerability in node-forge versions
    1.3.1 and below enables remote, unauthenticated attackers to craft deep
    ASN.1 structures that trigger unbounded recursive parsing. This leads to a
    Denial-of-Service (DoS) via stack exhaustion when parsing untrusted DER
    inputs.
  - Reported by Hunter Wodzenski.
  - CVE ID: [CVE-2025-66031](https://www.cve.org/CVERecord?id=CVE-2025-66031)
  - GHSA ID: [GHSA-554w-wpv2-vw27](https://github.com/digitalbazaar/forge/security/advisories/GHSA-554w-wpv2-vw27)
- **MODERATE**: ASN.1 OID Integer Truncation
  - An Integer Overflow (CWE-190) vulnerability in node-forge versions 1.3.1
    and below enables remote, unauthenticated attackers to craft ASN.1
    structures containing OIDs with oversized arcs. These arcs may be decoded
    as smaller, trusted OIDs due to 32-bit bitwise truncation, enabling the
    bypass of downstream OID-based security decisions.
  - Reported by Hunter Wodzenski.
  - CVE ID: [CVE-2025-66030](https://www.cve.org/CVERecord?id=CVE-2025-66030)
  - GHSA ID: [GHSA-65ch-62r8-g69g](https://github.com/digitalbazaar/forge/security/advisories/GHSA-65ch-62r8-g69g)

### Fixed
- [asn1] Fix for vulnerability identified by CVE-2025-12816 PKCS#12 MAC
  verification bypass due to missing macData enforcement and improper
  asn1.validate routine.
- [asn1] Add `fromDer()` max recursion depth check.
  - Add a `asn1.maxDepth` global configurable maximum depth of 256.
  - Add a `asn1.fromDer()` per-call `maxDepth` option.
  - **NOTE**: The default maximum is assumed to be higher than needed for valid
    data. If this assumption is false then this could be a breaking change.
    Please file an issue if there are use cases that need a higher maximum.
  - **NOTE**: The per-call `maxDepth` parameter has not been exposed up through
    all of the API stack due to the complexities involved. Please file an issue
    if there are use cases that require this instead of changing the default
    maximum.
- [asn1] Improve OID handling.
  - Error on parsed OID values larger than `2**32 - 1`.
  - Error on DER OID values larger than `2**53 - 1 `.

## 1.3.1 - 2022-03-29

### Fixed
- RFC 3447 and RFC 8017 allow for optional `DigestAlgorithm` `NULL` parameters
  for `sha*` algorithms and require `NULL` parameters for `md2` and `md5`
  algorithms.

## 1.3.0 - 2022-03-17

### Security
- Three RSA PKCS#1 v1.5 signature verification issues were reported by Moosa
  Yahyazadeh (moosa-yahyazadeh@uiowa.edu).
- **HIGH**: Leniency in checking `digestAlgorithm` structure can lead to
  signature forgery.
  - The code is lenient in checking the digest algorithm structure. This can
    allow a crafted structure that steals padding bytes and uses unchecked
    portion of the PKCS#1 encoded message to forge a signature when a low
    public exponent is being used. For more information, please see
    ["Bleichenbacher's RSA signature forgery based on implementation
    error"](https://mailarchive.ietf.org/arch/msg/openpgp/5rnE9ZRN1AokBVj3VqblGlP63QE/)
    by Hal Finney.
  - CVE ID: [CVE-2022-24771](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-24771)
  - GHSA ID: [GHSA-cfm4-qjh2-4765](https://github.com/digitalbazaar/forge/security/advisories/GHSA-cfm4-qjh2-4765)
- **HIGH**: Failing to check tailing garbage bytes can lead to signature
  forgery.
  - The code does not check for tailing garbage bytes after decoding a
    `DigestInfo` ASN.1 structure. This can allow padding bytes to be removed
    and garbage data added to forge a signature when a low public exponent is
    being used.  For more information, please see ["Bleichenbacher's RSA
    signature forgery based on implementation
    error"](https://mailarchive.ietf.org/arch/msg/openpgp/5rnE9ZRN1AokBVj3VqblGlP63QE/)
    by Hal Finney.
  - CVE ID: [CVE-2022-24772](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-24772)
  - GHSA ID: [GHSA-x4jg-mjrx-434g](https://github.com/digitalbazaar/forge/security/advisories/GHSA-x4jg-mjrx-434g)
- **MEDIUM**: Leniency in checking type octet.
  - `DigestInfo` is not properly checked for proper ASN.1 structure. This can
    lead to successful verification with signatures that contain invalid
    structures but a valid digest.
  - CVE ID: [CVE-2022-24773](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-24773)
  - GHSA ID: [GHSA-2r2c-g63r-vccr](https://github.com/digitalbazaar/forge/security/advisories/GHSA-2r2c-g63r-vccr)

### Fixed
- [asn1] Add fallback to pretty print invalid UTF8 data.
- [asn1] `fromDer` is now more strict and will default to ensuring all input
  bytes are parsed or throw an error. A new option `parseAllBytes` can disable
  this behavior.
  - **NOTE**: The previous behavior is being changed since it can lead to
    security issues with crafted inputs. It is possible that code doing custom
    DER parsing may need to adapt to this new behavior and optional flag.
- [rsa] Add and use a validator to check for proper structure of parsed ASN.1
  `RSASSA-PKCS-v1_5` `DigestInfo` data. Additionally check that the hash
  algorithm identifier is a known value from RFC 8017
  `PKCS1-v1-5DigestAlgorithms`. An invalid `DigestInfo` or algorithm identifier
  will now throw an error.
  - **NOTE**: The previous lenient behavior is being changed to be more strict
    since it could lead to security issues with crafted inputs. It is possible
    that code may have to handle the errors from these stricter checks.

### Added
- [oid] Added missing RFC 8017 PKCS1-v1-5DigestAlgorithms algorithm
  identifiers:
  - `1.2.840.113549.2.2` / `md2`
  - `2.16.840.1.101.3.4.2.4` / `sha224`
  - `2.16.840.1.101.3.4.2.5` / `sha512-224`
  - `2.16.840.1.101.3.4.2.6` / `sha512-256`

## 1.2.1 - 2022-01-11

### Fixed
- [tests]: Load entire module to improve top-level testing and coverage
  reporting.
- [log]: Refactor logging setup to avoid use of `URLSearchParams`.

## 1.2.0 - 2022-01-07

### Fixed
- [x509] 'Expected' and 'Actual' issuers were backwards in verification failure
  message.
- [prime,prime.worker] Add type to messages and ignore unexpected messages.

### Added
- [oid,x509]: Added OID `1.3.14.3.2.29 / sha1WithRSASignature` for sha1 with
  RSA. Considered a deprecated equivalent to `1.2.840.113549.1.1.5 /
  sha1WithRSAEncryption`. See [discussion and
  links](https://github.com/digitalbazaar/forge/issues/825).

### Changed
- [x509]: Reduce duplicate code. Add helper function to create a signature
  digest given an signature algorithm OID. Add helper function to verify
  signatures.

## 1.1.0 - 2022-01-06

### Fixed
- [x509]: Correctly compute certificate issuer and subject hashes to match
  behavior of openssl.
- [pem]: Accept certificate requests with "NEW" in the label. "BEGIN NEW
  CERTIFICATE REQUEST" handled as "BEGIN CERTIFICATE REQUEST".

## 1.0.0 - 2022-01-04

### Notes
- **1.0.0**!
- This project is over a decade old! Time for a 1.0.0 release.
- The URL related changes may expose bugs in some of the networking related
  code (unrelated to the much wider used cryptography code). The automated and
  manual test coverage for this code is weak at best. Issues or patches to
  update the code or tests would be appreciated.

### Removed
- **SECURITY**, **BREAKING**: Remove `forge.debug` API. The API has the
  potential for prototype pollution. This API was only briefly used by the
  maintainers for internal project debug purposes and was never intended to be
  used with untrusted user inputs. This API was not documented or advertised
  and is being removed rather than fixed.
- **SECURITY**, **BREAKING**: Remove `forge.util.parseUrl()` (and
  `forge.http.parseUrl` alias) and use the [WHATWG URL
  Standard](https://url.spec.whatwg.org/). `URL` is supported by modern
  browsers and modern Node.js. This change is needed to address URL parsing
  security issues. If `forge.util.parseUrl()` is used directly or through
  `forge.xhr` or `forge.http` APIs, and support is needed for environments
  without `URL` support, then a polyfill must be used.
- **BREAKING**: Remove `forge.task` API. This API was never used, documented,
  or advertised by the maintainers. If anyone was using this API and wishes to
  continue development it in other project, please let the maintainers know.
  Due to use in the test suite, a modified version is located in
  `tests/support/`.
- **BREAKING**: Remove `forge.util.makeLink`, `forge.util.makeRequest`,
  `forge.util.parseFragment`, `forge.util.getQueryVariables`. Replace with
  `URL`, `URLSearchParams`, and custom code as needed.

### Changed
- **BREAKING**: Increase supported Node.js version to 6.13.0 for URL support.
- **BREAKING**: Renamed `master` branch to `main`.
- **BREAKING**: Release process updated to use tooling that prefixes versions
  with `v`. Other tools, scripts, or scanners may need to adapt.
- **BREAKING**: Remove docs related to Bower and
  [forge-dist](https://github.com/digitalbazaar/forge-dist). Install using
  [another method](./README.md#installation).

### Added
- OIDs for `surname`, `title`, and `givenName`.

### Fixed
- **BREAKING**: OID 2.5.4.5 name fixed from `serialName` to `serialNumber`.
  Depending on how applications used this id to name association it could cause
  compatibility issues.

## 0.10.0 - 2020-09-01

### Changed
- **BREAKING**: Node.js 4 no longer supported. The code *may* still work, and
  non-invasive patches to keep it working will be considered. However, more
  modern tools no longer support old Node.js versions making testing difficult.

### Removed
- **BREAKING**: Remove `util.getPath`, `util.setPath`, and `util.deletePath`.
  `util.setPath` had a potential prototype pollution security issue when used
  with unsafe inputs. These functions are not used by `forge` itself. They date
  from an early time when `forge` was targeted at providing general helper
  functions. The library direction changed to be more focused on cryptography.
  Many other excellent libraries are more suitable for general utilities. If
  you need a replacement for these functions, consider `get`, `set`, and `unset`
  from [lodash](https://lodash.com/). But also consider the potential similar
  security issues with those APIs.

## 0.9.2 - 2020-09-01

### Changed
- Added `util.setPath` security note to function docs and to README.

### Notes
- **SECURITY**: The `util.setPath` function has the potential to cause
  prototype pollution if used with unsafe input.
  - This function is **not** used internally by `forge`.
  - The rest of the library is unaffected by this issue.
  - **Do not** use unsafe input with this function.
  - Usage with known input should function as expected. (Including input
    intentionally using potentially problematic keys.)
  - No code changes will be made to address this issue in 0.9.x. The current
    behavior *could* be considered a feature rather than a security issue.
    0.10.0 will be released that removes `util.getPath` and `util.setPath`.
    Consider `get` and `set` from [lodash](https://lodash.com/) if you need
    replacements. But also consider the potential similar security issues with
    those APIs.
  - https://snyk.io/vuln/SNYK-JS-NODEFORGE-598677
  - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-7720

## 0.9.1 - 2019-09-26

### Fixed
- Ensure DES-CBC given IV is long enough for block size.

## 0.9.0 - 2019-09-04

### Added
- Add ed25519.publicKeyFromAsn1 and ed25519.privateKeyFromAsn1 APIs.
- A few OIDs used in EV certs.

### Fixed
- Improve ed25519 NativeBuffer check.

## 0.8.5 - 2019-06-18

### Fixed
- Remove use of `const`.

## 0.8.4 - 2019-05-22

### Changed
- Replace all instances of Node.js `new Buffer` with `Buffer.from` and `Buffer.alloc`.

## 0.8.3 - 2019-05-15

### Fixed
- Use basic character set for code.

## 0.8.2 - 2019-03-18

### Fixed
- Fix tag calculation when continuing an AES-GCM block.

### Changed
- Switch to eslint.

## 0.8.1 - 2019-02-23

### Fixed
- Fix off-by-1 bug with kem random generation.

## 0.8.0 - 2019-01-31

### Fixed
- Handle creation of certificates with `notBefore` and `notAfter` dates less
  than Jan 1, 1950 or greater than or equal to Jan 1, 2050.

### Added
- Add OID 2.5.4.13 "description".
- Add OID 2.16.840.1.113730.1.13 "nsComment".
  - Also handle extension when creating a certificate.
- `pki.verifyCertificateChain`:
  - Add `validityCheckDate` option to allow checking the certificate validity
    period against an arbitrary `Date` or `null` for no check at all. The
    current date is used by default.
- `tls.createConnection`:
  - Add `verifyOptions` option that passes through to
    `pki.verifyCertificateChain`. Can be used for the above `validityCheckDate`
    option.

### Changed
- Support WebCrypto API in web workers.
- `rsa.generateKeyPair`:
  - Use `crypto.generateKeyPair`/`crypto.generateKeyPairSync` on Node.js if
    available (10.12.0+) and not in pure JS mode.
  - Use JS fallback in `rsa.generateKeyPair` if `prng` option specified since
    this isn't supported by current native APIs.
  - Only run key generation comparison tests if keys will be deterministic.
- PhantomJS is deprecated, now using Headless Chrome with Karma.
- **Note**: Using Headless Chrome vs PhantomJS may cause newer JS features to
  slip into releases without proper support for older runtimes and browsers.
  Please report such issues and they will be addressed.
- `pki.verifyCertificateChain`:
  - Signature changed to `(caStore, chain, options)`. Older `(caStore, chain,
    verify)` signature is still supported. New style is to to pass in a
    `verify` option.

## 0.7.6 - 2018-08-14

### Added
- Test on Node.js 10.x.
- Support for PKCS#7 detached signatures.

### Changed
- Improve webpack/browser detection.

## 0.7.5 - 2018-03-30

### Fixed
- Remove use of `const`.

## 0.7.4 - 2018-03-07

### Fixed
- Potential regex denial of service in form.js.

### Added
- Support for ED25519.
- Support for baseN/base58.

## 0.7.3 - 2018-03-05

- Re-publish with npm 5.6.0 due to file timestamp issues.

## 0.7.2 - 2018-02-27

### Added
- Support verification of SHA-384 certificates.
- `1.2.840.10040.4.3'`/`dsa-with-sha1` OID.

### Fixed
- Support importing PKCS#7 data with no certificates. RFC 2315 sec 9.1 states
  certificates are optional.
- `asn1.equals` loop bug.
- Fortuna implementation bugs.

## 0.7.1 - 2017-03-27

### Fixed

- Fix digestLength for hashes based on SHA-512.

## 0.7.0 - 2017-02-07

### Fixed

- Fix test looping bugs so all tests are run.
- Improved ASN.1 parsing. Many failure cases eliminated. More sanity checks.
  Better behavior in default mode of parsing BIT STRINGs. Better handling of
  parsed BIT STRINGs in `toDer()`. More tests.
- Improve X.509 BIT STRING handling by using new capture modes.

### Changed

- Major refactor to use CommonJS plus a browser build system.
- Updated tests, examples, docs.
- Updated dependencies.
- Updated flash build system.
- Improve OID mapping code.
- Change test servers from Python to JavaScript.
- Improve PhantomJS support.
- Move Bower/bundle support to
  [forge-dist](https://github.com/digitalbazaar/forge-dist).
- **BREAKING**: Require minimal digest algorithm dependencies from individual
  modules.
- Enforce currently supported bit param values for byte buffer access. May be
  **BREAKING** for code that depended on unspecified and/or incorrect behavior.
- Improve `asn1.prettyPrint()` BIT STRING display.

### Added

- webpack bundler support via `npm run build`:
  - Builds `.js`, `.min.js`, and basic sourcemaps.
  - Basic build: `forge.js`.
  - Build with extra utils and networking support: `forge.all.js`.
  - Build WebWorker support: `prime.worker.js`.
- Browserify support in package.json.
- Karma browser testing.
- `forge.options` field.
- `forge.options.usePureJavaScript` flag.
- `forge.util.isNodejs` flag (used to select "native" APIs).
- Run PhantomJS tests in Travis-CI.
- Add "Donations" section to README.
- Add IRC to "Contact" section of README.
- Add "Security Considerations" section to README.
- Add pbkdf2 usePureJavaScript test.
- Add rsa.generateKeyPair async and usePureJavaScript tests.
- Add .editorconfig support.
- Add `md.all.js` which includes all digest algorithms.
- Add asn1 `equals()` and `copy()`.
- Add asn1 `validate()` capture options for BIT STRING contents and value.

### Removed

- **BREAKING**: Can no longer call `forge({...})` to create new instances.
- Remove a large amount of old cruft.

### Migration from 0.6.x to 0.7.x

- (all) If you used the feature to create a new forge instance with new
  configuration options you will need to rework your code. That ability has
  been removed due to implementation complexity. The main rare use was to set
  the option to use pure JavaScript. That is now available as a library global
  flag `forge.options.usePureJavaScript`.
- (npm,bower) If you used the default main file there is little to nothing to
  change.
- (npm) If you accessed a sub-resource like `forge/js/pki` you should either
  switch to just using the main `forge` and access `forge.pki` or update to
  `forge/lib/pki`.
- (bower) If you used a sub-resource like `forge/js/pki` you should switch to
  just using `forge` and access `forge.pki`. The bower release bundles
  everything in one minified file.
- (bower) A configured workerScript like
  `/bower_components/forge/js/prime.worker.js` will need to change to
  `/bower_components/forge/dist/prime.worker.min.js`.
- (all) If you used the networking support or flash socket support, you will
  need to use a custom build and/or adjust where files are loaded from. This
  functionality is not included in the bower distribution by default and is
  also now in a different directory.
- (all) The library should now directly support building custom bundles with
  webpack, browserify, or similar.
- (all) If building a custom bundle ensure the correct dependencies are
  included. In particular, note there is now a `md.all.js` file to include all
  digest algorithms. Individual files limit what they include by default to
  allow smaller custom builds. For instance, `pbdkf2.js` has a `sha1` default
  but does not include any algorithm files by default. This allows the
  possibility to include only `sha256` without the overhead of `sha1` and
  `sha512`.

### Notes

- This major update requires updating the version to 0.7.x. The existing
  work-in-progress "0.7.x" branch will be painfully rebased on top of this new
  0.7.x and moved forward to 0.8.x or later as needed.
- 0.7.x is a start of simplifying forge based on common issues and what has
  appeared to be the most common usage. Please file issues with feedback if the
  changes are problematic for your use cases.

## 0.6.x - 2016 and earlier

- See Git commit log or https://github.com/digitalbazaar/forge.
