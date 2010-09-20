/**
 * A Javascript implementation of Transport Layer Security (TLS).
 *
 * @author Dave Longley
 *
 * Copyright (c) 2009-2010 Digital Bazaar, Inc. All rights reserved.
 * 
 * The TLS Handshake Protocol involves the following steps:
 *
 * - Exchange hello messages to agree on algorithms, exchange
 * random values, and check for session resumption.
 * 
 * - Exchange the necessary cryptographic parameters to allow the
 * client and server to agree on a premaster secret.
 * 
 * - Exchange certificates and cryptographic information to allow
 * the client and server to authenticate themselves.
 * 
 * - Generate a master secret from the premaster secret and
 * exchanged random values.
 * 
 * - Provide security parameters to the record layer.
 * 
 * - Allow the client and server to verify that their peer has
 * calculated the same security parameters and that the handshake
 * occurred without tampering by an attacker.
 * 
 * Up to 4 different messages may be sent during a key exchange.
 * The server certificate, the server key exchange, the client
 * certificate, and the client key exchange.
 * 
 * A typical handshake (from the client's perspective).
 * 
 * 1. Client sends ClientHello.
 * 2. Client receives ServerHello.
 * 3. Client receives optional Certificate.
 * 4. Client receives optional ServerKeyExchange.
 * 5. Client receives ServerHelloDone.
 * 6. Client sends optional Certificate.
 * 7. Client sends ClientKeyExchange.
 * 8. Client sends optional CertificateVerify.
 * 9. Client sends ChangeCipherSpec.
 * 10. Client sends Finished.
 * 11. Client receives ChangeCipherSpec.
 * 12. Client receives Finished.
 * 13. Client sends/receives application data.
 *
 * To reuse an existing session:
 * 
 * 1. Client sends ClientHello with session ID for reuse.
 * 2. Client receives ServerHello with same session ID if reusing.
 * 3. Client receives ChangeCipherSpec message if reusing.
 * 4. Client receives Finished.
 * 5. Client sends ChangeCipherSpec.
 * 6. Client sends Finished.
 * 
 * Note: Client ignores HelloRequest if in the middle of a handshake.
 * 
 * Record Layer:
 * 
 * The record layer fragments information blocks into TLSPlaintext
 * records carrying data in chunks of 2^14 bytes or less. Client message
 * boundaries are not preserved in the record layer (i.e., multiple
 * client messages of the same ContentType MAY be coalesced into a single
 * TLSPlaintext record, or a single message MAY be fragmented across
 * several records).
 * 
 * struct {
 *    uint8 major;
 *    uint8 minor;
 * } ProtocolVersion;
 * 
 * struct {
 *    ContentType type;
 *    ProtocolVersion version;
 *    uint16 length;
 *    opaque fragment[TLSPlaintext.length];
 * } TLSPlaintext;
 * 
 * type:
 *    The higher-level protocol used to process the enclosed fragment.
 * 
 * version:
 *    The version of the protocol being employed. TLS Version 1.2
 *    uses version {3, 3}. TLS Version 1.0 uses version {3, 1}. Note
 *    that a client that supports multiple versions of TLS may not know
 *    what version will be employed before it receives the ServerHello.
 * 
 * length:
 *    The length (in bytes) of the following TLSPlaintext.fragment. The
 *    length MUST NOT exceed 2^14 = 16384 bytes.
 * 
 * fragment:
 *    The application data. This data is transparent and treated as an
 *    independent block to be dealt with by the higher-level protocol
 *    specified by the type field.
 * 
 * Implementations MUST NOT send zero-length fragments of Handshake,
 * Alert, or ChangeCipherSpec content types. Zero-length fragments of
 * Application data MAY be sent as they are potentially useful as a
 * traffic analysis countermeasure.
 * 
 * Note: Data of different TLS record layer content types MAY be
 * interleaved. Application data is generally of lower precedence for
 * transmission than other content types. However, records MUST be
 * delivered to the network in the same order as they are protected by
 * the record layer. Recipients MUST receive and process interleaved
 * application layer traffic during handshakes subsequent to the first
 * one on a connection.
 * 
 * struct {
 *    ContentType type;       // same as TLSPlaintext.type
 *    ProtocolVersion version;// same as TLSPlaintext.version
 *    uint16 length;
 *    opaque fragment[TLSCompressed.length];
 * } TLSCompressed;
 * 
 * length:
 *    The length (in bytes) of the following TLSCompressed.fragment.
 *    The length MUST NOT exceed 2^14 + 1024.
 * 
 * fragment:
 *    The compressed form of TLSPlaintext.fragment.
 * 
 * Note: A CompressionMethod.null operation is an identity operation;
 * no fields are altered. In this implementation, since no compression
 * is supported, uncompressed records are always the same as compressed
 * records.
 * 
 * Encryption Information:
 * 
 * The encryption and MAC functions translate a TLSCompressed structure
 * into a TLSCiphertext. The decryption functions reverse the process. 
 * The MAC of the record also includes a sequence number so that missing,
 * extra, or repeated messages are detectable.
 * 
 * struct {
 *    ContentType type;
 *    ProtocolVersion version;
 *    uint16 length;
 *    select (SecurityParameters.cipher_type) {
 *       case stream: GenericStreamCipher;
 *       case block:  GenericBlockCipher;
 *       case aead:   GenericAEADCipher;
 *    } fragment;
 * } TLSCiphertext;
 * 
 * type:
 *    The type field is identical to TLSCompressed.type.
 * 
 * version:
 *    The version field is identical to TLSCompressed.version.
 * 
 * length:
 *    The length (in bytes) of the following TLSCiphertext.fragment.
 *    The length MUST NOT exceed 2^14 + 2048.
 * 
 * fragment:
 *    The encrypted form of TLSCompressed.fragment, with the MAC.
 * 
 * Note: Only CBC Block Ciphers are supported by this implementation.
 * 
 * The TLSCompressed.fragment structures are converted to/from block
 * TLSCiphertext.fragment structures.
 * 
 * struct {
 *    opaque IV[SecurityParameters.record_iv_length];
 *    block-ciphered struct {
 *        opaque content[TLSCompressed.length];
 *        opaque MAC[SecurityParameters.mac_length];
 *        uint8 padding[GenericBlockCipher.padding_length];
 *        uint8 padding_length;
 *    };
 * } GenericBlockCipher;
 * 
 * The MAC is generated as described in Section 6.2.3.1.
 * 
 * IV:
 *    The Initialization Vector (IV) SHOULD be chosen at random, and
 *    MUST be unpredictable. Note that in versions of TLS prior to 1.1,
 *    there was no IV field, and the last ciphertext block of the
 *    previous record (the "CBC residue") was used as the IV. This was
 *    changed to prevent the attacks described in [CBCATT]. For block
 *    ciphers, the IV length is of length
 *    SecurityParameters.record_iv_length, which is equal to the
 *    SecurityParameters.block_size.
 * 
 * padding:
 *    Padding that is added to force the length of the plaintext to be
 *    an integral multiple of the block cipher's block length. The
 *    padding MAY be any length up to 255 bytes, as long as it results
 *    in the TLSCiphertext.length being an integral multiple of the
 *    block length. Lengths longer than necessary might be desirable to
 *    frustrate attacks on a protocol that are based on analysis of the
 *    lengths of exchanged messages. Each uint8 in the padding data
 *    vector MUST be filled with the padding length value. The receiver
 *    MUST check this padding and MUST use the bad_record_mac alert to
 *    indicate padding errors.
 *
 * padding_length:
 *    The padding length MUST be such that the total size of the
 *    GenericBlockCipher structure is a multiple of the cipher's block
 *    length. Legal values range from zero to 255, inclusive. This
 *    length specifies the length of the padding field exclusive of the
 *    padding_length field itself.
 *
 * The encrypted data length (TLSCiphertext.length) is one more than the
 * sum of SecurityParameters.block_length, TLSCompressed.length,
 * SecurityParameters.mac_length, and padding_length.
 *
 * Example: If the block length is 8 bytes, the content length
 * (TLSCompressed.length) is 61 bytes, and the MAC length is 20 bytes,
 * then the length before padding is 82 bytes (this does not include the
 * IV. Thus, the padding length modulo 8 must be equal to 6 in order to
 * make the total length an even multiple of 8 bytes (the block length).
 * The padding length can be 6, 14, 22, and so on, through 254. If the
 * padding length were the minimum necessary, 6, the padding would be 6
 * bytes, each containing the value 6. Thus, the last 8 octets of the
 * GenericBlockCipher before block encryption would be xx 06 06 06 06 06
 * 06 06, where xx is the last octet of the MAC.
 *
 * Note: With block ciphers in CBC mode (Cipher Block Chaining), it is
 * critical that the entire plaintext of the record be known before any
 * ciphertext is transmitted. Otherwise, it is possible for the
 * attacker to mount the attack described in [CBCATT].
 *
 * Implementation note: Canvel et al. [CBCTIME] have demonstrated a
 * timing attack on CBC padding based on the time required to compute
 * the MAC. In order to defend against this attack, implementations
 * MUST ensure that record processing time is essentially the same
 * whether or not the padding is correct. In general, the best way to
 * do this is to compute the MAC even if the padding is incorrect, and
 * only then reject the packet. For instance, if the pad appears to be
 * incorrect, the implementation might assume a zero-length pad and then
 * compute the MAC. This leaves a small timing channel, since MAC
 * performance depends, to some extent, on the size of the data fragment,
 * but it is not believed to be large enough to be exploitable, due to
 * the large block size of existing MACs and the small size of the
 * timing signal.
 */
(function()
{
   // local alias for forge stuff
   var forge = window.forge;
   
   /**
    * Generates pseudo random bytes by mixing the result of two hash
    * functions, MD5 and SHA-1.
    * 
    * prf_TLS1(secret, label, seed) =
    *    P_MD5(S1, label + seed) XOR P_SHA-1(S2, label + seed);
    * 
    * Each P_hash function functions as follows:
    * 
    * P_hash(secret, seed) = HMAC_hash(secret, A(1) + seed) +
    *                        HMAC_hash(secret, A(2) + seed) +
    *                        HMAC_hash(secret, A(3) + seed) + ...
    * A() is defined as:
    *   A(0) = seed
    *   A(i) = HMAC_hash(secret, A(i-1))
    * 
    * The '+' operator denotes concatenation.
    * 
    * As many iterations A(N) as are needed are performed to generate enough
    * pseudo random byte output. If an iteration creates more data than is
    * necessary, then it is truncated.
    * 
    * Therefore:
    * A(1) = HMAC_hash(secret, A(0))
    *      = HMAC_hash(secret, seed)
    * A(2) = HMAC_hash(secret, A(1))
    *      = HMAC_hash(secret, HMAC_hash(secret, seed))
    * 
    * Therefore:
    * P_hash(secret, seed) =
    *    HMAC_hash(secret, HMAC_hash(secret, A(0)) + seed) +
    *    HMAC_hash(secret, HMAC_hash(secret, A(1)) + seed) +
    *    ...
    * 
    * Therefore:
    * P_hash(secret, seed) =
    *    HMAC_hash(secret, HMAC_hash(secret, seed) + seed) +
    *    HMAC_hash(secret, HMAC_hash(secret, HMAC_hash(secret, seed)) + seed) +
    *    ...
    * 
    * @param secret the secret to use.
    * @param label the label to use.
    * @param seed the seed value to use.
    * @param length the number of bytes to generate.
    * 
    * @return the pseudo random bytes in a byte buffer.
    */
   var prf_TLS1 = function(secret, label, seed, length)
   {
      var rval = forge.util.createBuffer();
      
      /* For TLS 1.0, the secret is split in half, into two secrets of equal
         length. If the secret has an odd length then the last byte of the
         first half will be the same as the first byte of the second. The
         length of the two secrets is half of the secret rounded up.
       */
      var idx = (secret.length >> 1);
      var slen = idx + (secret.length & 1);
      var s1 = secret.substr(0, slen);
      var s2 = secret.substr(idx, slen);
      var ai = forge.util.createBuffer();
      var hmac = forge.hmac.create();
      seed = label + seed;
      
      // determine the number of iterations that must be performed to generate
      // enough output bytes, md5 creates 16 byte hashes, sha1 creates 20
      var md5itr = Math.ceil(length / 16);
      var sha1itr = Math.ceil(length / 20);
      
      // do md5 iterations
      hmac.start('MD5', s1);
      var md5bytes = forge.util.createBuffer();
      ai.putBytes(seed);
      for(var i = 0; i < md5itr; ++i)
      {
         // HMAC_hash(secret, A(i-1))
         hmac.start(null, null);
         hmac.update(ai.getBytes());
         ai.putBuffer(hmac.digest());
         
         // HMAC_hash(secret, A(i) + seed)
         hmac.start(null, null);
         hmac.update(ai.bytes() + seed);
         md5bytes.putBuffer(hmac.digest());
      }
      
      // do sha1 iterations
      hmac.start('SHA1', s2);
      var sha1bytes = forge.util.createBuffer();
      ai.clear();
      ai.putBytes(seed);
      for(var i = 0; i < sha1itr; ++i)
      {
         // HMAC_hash(secret, A(i-1))
         hmac.start(null, null);
         hmac.update(ai.getBytes());
         ai.putBuffer(hmac.digest());
         
         // HMAC_hash(secret, A(i) + seed)
         hmac.start(null, null);
         hmac.update(ai.bytes() + seed);
         sha1bytes.putBuffer(hmac.digest());
      }
      
      // XOR the md5 bytes with the sha1 bytes
      rval.putBytes(forge.util.xorBytes(
         md5bytes.getBytes(), sha1bytes.getBytes(), length));
      
      return rval;
   };
   
   /**
    * Generates pseudo random bytes using a SHA256 algorithm. For TLS 1.2.
    * 
    * @param secret the secret to use.
    * @param label the label to use.
    * @param seed the seed value to use.
    * @param length the number of bytes to generate.
    * 
    * @return the pseudo random bytes in a byte buffer.
    */
   var prf_sha256 = function(secret, label, seed, length)
   {
      // FIXME: implement me for TLS 1.2
   };
   
   /**
    * Gets a MAC for a record using the SHA-1 hash algorithm.
    * 
    * @param key the mac key.
    * @param state the sequence number (array of two 32-bit integers).
    * @param record the record.
    * 
    * @return the sha-1 hash (20 bytes) for the given record.
    */
   var hmac_sha1 = function(key, seqNum, record)
   {
      /* MAC is computed like so:
      HMAC_hash(
         key, seqNum +
            TLSCompressed.type +
            TLSCompressed.version +
            TLSCompressed.length +
            TLSCompressed.fragment)
      */
      var hmac = forge.hmac.create();
      hmac.start('SHA1', key);
      var b = forge.util.createBuffer();
      b.putInt32(seqNum[0]);
      b.putInt32(seqNum[1]);
      b.putByte(record.type);
      b.putByte(record.version.major);
      b.putByte(record.version.minor);
      b.putInt16(record.length);
      b.putBytes(record.fragment.bytes());
      hmac.update(b.getBytes());
      return hmac.digest().getBytes();
   };
   
   /**
    * Compresses the TLSPlaintext record into a TLSCompressed record using
    * the deflate algorithm.
    * 
    * @param c the TLS connection.
    * @param record the TLSPlaintext record to compress.
    * @param s the ConnectionState to use.
    * 
    * @return true on success, false on failure.
    */
   var deflate = function(c, record, s)
   {
      var rval = false;
      
      try
      {
         var bytes = c.deflate(record.fragment.getBytes());
         record.fragment = forge.util.createBuffer(bytes);
         record.length = bytes.length;
         rval = true;
      }
      catch(ex)
      {
         // deflate error, fail out
      }
      
      return rval;
   };
   
   /**
    * Decompresses the TLSCompressed record into a TLSPlaintext record using
    * the deflate algorithm.
    * 
    * @param c the TLS connection.
    * @param record the TLSCompressed record to decompress.
    * @param s the ConnectionState to use.
    * 
    * @return true on success, false on failure.
    */
   var inflate = function(c, record, s)
   {
      var rval = false;
      
      try
      {
         var bytes = c.inflate(record.fragment.getBytes());
         record.fragment = forge.util.createBuffer(bytes);
         record.length = bytes.length;
         rval = true;
      }
      catch(ex)
      {
         // inflate error, fail out
      }
      
      return rval;
   };
   
   /**
    * Encrypts the TLSCompressed record into a TLSCipherText record using
    * AES-128 in CBC mode.
    * 
    * @param record the TLSCompressed record to encrypt.
    * @param s the ConnectionState to use.
    * 
    * @return true on success, false on failure.
    */
   var encrypt_aes_128_cbc_sha1 = function(record, s)
   {
      var rval = false;
      
      // append MAC to fragment, update sequence number
      var mac = s.macFunction(s.macKey, s.sequenceNumber, record);
      record.fragment.putBytes(mac);
      s.updateSequenceNumber();
      
      // TODO: TLS 1.1 & 1.2 use an explicit IV every time to protect
      // against CBC attacks
      // var iv = forge.random.getBytes(16);
      
      // use the pre-generated IV when initializing for TLS 1.0, otherwise
      // use the residue from the previous encryption
      var iv = s.cipherState.init ? null : s.cipherState.iv;
      s.cipherState.init = true;
      
      // start cipher
      var cipher = s.cipherState.cipher;
      cipher.start(iv);
      
      // TODO: TLS 1.1 & 1.2 write IV into output
      //cipher.output.putBytes(iv);
      
      // do encryption (default padding is appropriate)
      cipher.update(record.fragment);
      if(cipher.finish(encrypt_aes_128_cbc_sha1_padding))
      {
         // set record fragment to encrypted output
         record.fragment = cipher.output;
         record.length = record.fragment.length();
         rval = true;
      }
      
      return rval;
   };
   
   /**
    * Handles padding for aes_128_cbc_sha1 in encrypt mode.
    * 
    * @param blockSize the block size.
    * @param input the input buffer.
    * @param decrypt true in decrypt mode, false in encrypt mode.
    * 
    * @return true on success, false on failure.
    */
   var encrypt_aes_128_cbc_sha1_padding = function(blockSize, input, decrypt)
   {
      /* The encrypted data length (TLSCiphertext.length) is one more than
      the sum of SecurityParameters.block_length, TLSCompressed.length,
      SecurityParameters.mac_length, and padding_length.
      
      The padding may be any length up to 255 bytes long, as long as it
      results in the TLSCiphertext.length being an integral multiple of
      the block length. Lengths longer than necessary might be desirable
      to frustrate attacks on a protocol based on analysis of the lengths
      of exchanged messages. Each uint8 in the padding data vector must be
      filled with the padding length value.
      
      The padding length should be such that the total size of the
      GenericBlockCipher structure is a multiple of the cipher's block
      length. Legal values range from zero to 255, inclusive. This length
      specifies the length of the padding field exclusive of the
      padding_length field itself.
      
      This is slightly different from PKCS#7 because the padding value is 1
      less than the actual number of padding bytes if you include the
      padding_length uint8 itself as a padding byte.
      */
      if(!decrypt)
      {
         // get the number of padding bytes required to reach the blockSize
         // and subtract 1 to make room for the padding_length uint8 but
         // add it during fillWithByte
         var padding = (input.length() == blockSize) ?
            (blockSize - 1) : (blockSize - input.length() - 1);
         input.fillWithByte(padding, padding + 1);
      }
      return true;
   };
   
   /**
    * Handles padding for aes_128_cbc_sha1 in decrypt mode.
    * 
    * @param blockSize the block size.
    * @param output the output buffer.
    * @param decrypt true in decrypt mode, false in encrypt mode.
    * 
    * @return true on success, false on failure.
    */
   var decrypt_aes_128_cbc_sha1_padding = function(blockSize, output, decrypt)
   {
      var rval = true;
      if(decrypt)
      {
         /* The last byte in the output specifies the number of padding bytes
            not including itself. Each of the padding bytes has the same value
            as that last byte (known as the padding_length). Here we check all
            padding bytes to ensure they have the value of padding_length even
            if one of them is bad in order to ward-off timing attacks.
          */
         var len = output.length();
         var paddingLength = output.last();
         for(var i = len - 1 - paddingLength; i < len - 1; ++i)
         {
            rval = rval && (output.at(i) == paddingLength);
         }
         if(rval)
         {
            // trim off padding bytes and last padding length byte
            output.truncate(paddingLength + 1);
         }
      }
      return rval;
   };
   
   /**
    * Decrypts a TLSCipherText record into a TLSCompressed record using
    * AES-128 in CBC mode.
    * 
    * @param record the TLSCipherText record to decrypt.
    * @param s the ConnectionState to use.
    * 
    * @return true on success, false on failure.
    */
   var decrypt_aes_128_cbc_sha1 = function(record, s)
   {
      var rval = false;
      
      // TODO: TLS 1.1 & 1.2 use an explicit IV every time to protect
      // against CBC attacks
      //var iv = record.fragment.getBytes(16);
      
      // use pre-generated IV when initializing for TLS 1.0, otherwise
      // use the residue from the previous decryption
      var iv = s.cipherState.init ? null : s.cipherState.iv;
      s.cipherState.init = true;
      
      // start cipher
      var cipher = s.cipherState.cipher;
      cipher.start(iv);
      
      // do decryption
      cipher.update(record.fragment);
      rval = cipher.finish(decrypt_aes_128_cbc_sha1_padding);
      
      // even if decryption fails, keep going to minimize timing attacks
      
      // decrypted data:
      // first (len - 20) bytes = application data
      // last 20 bytes          = MAC
      var macLen = s.macLength;
      
      // create a zero'd out mac
      var mac = '';
      for(var i = 0; i < macLen; ++i)
      {
         mac += String.fromCharCode(0);
      }
      
      // get fragment and mac
      var len = cipher.output.length();
      if(len >= macLen)
      {
         record.fragment = cipher.output.getBytes(len - macLen);
         mac = cipher.output.getBytes(macLen);
      }
      // bad data, but get bytes anyway to try to keep timing consistent
      else
      {
         record.fragment = cipher.output.getBytes();
      }
      record.fragment = forge.util.createBuffer(record.fragment);
      record.length = record.fragment.length();
      
      // see if data integrity checks out, update sequence number
      var mac2 = s.macFunction(s.macKey, s.sequenceNumber, record);
      s.updateSequenceNumber();
      rval = (mac2 === mac) && rval;
      return rval;
   };
   
   /**
    * Reads a TLS variable-length vector from a byte buffer.
    * 
    * Variable-length vectors are defined by specifying a subrange of legal
    * lengths, inclusively, using the notation <floor..ceiling>. When these
    * are encoded, the actual length precedes the vector's contents in the byte
    * stream. The length will be in the form of a number consuming as many
    * bytes as required to hold the vector's specified maximum (ceiling)
    * length. A variable-length vector with an actual length field of zero is
    * referred to as an empty vector.
    * 
    * @param b the byte buffer.
    * @param lenBytes the number of bytes required to store the length.
    * 
    * @return the resulting byte buffer.
    */
   var readVector = function(b, lenBytes)
   {
      var len = 0;
      switch(lenBytes)
      {
         case 1:
            len = b.getByte();
            break;
         case 2:
            len = b.getInt16();
            break;
         case 3:
            len = b.getInt24();
            break;
         case 4:
            len = b.getInt32();
            break;
      }
      
      // read vector bytes into a new buffer
      return forge.util.createBuffer(b.getBytes(len));
   };
   
   /**
    * Writes a TLS variable-length vector to a byte buffer.
    * 
    * @param b the byte buffer.
    * @param lenBytes the number of bytes required to store the length.
    * @param v the byte buffer vector.
    */
   var writeVector = function(b, lenBytes, v)
   {
      // encode length at the start of the vector, where the number
      // of bytes for the length is the maximum number of bytes it
      // would take to encode the vector's ceiling
      b.putInt(v.length(), lenBytes << 3);
      b.putBuffer(v);
   };
   
   /**
    * The tls implementation.
    */
   var tls = {};
   
   /**
    * Version: TLS 1.2 = 3.3, TLS 1.1 = 3.2, TLS 1.0 = 3.1. Both TLS 1.1
    * and TLS 1.2 were still too new (ie: openSSL didn't implement them) at
    * the time of this implementation so TLS 1.0 was implemented instead. 
    */
   tls.Version =
   {
      major: 3,
      minor: 1
   };
   
   /**
    * Maximum fragment size. True maximum is 16384, but we fragment before
    * that to allow for unusual small increases during compression.
    */
   tls.MaxFragment = (1 << 14) - 1024;
   
   /**
    * Whether this entity is considered the "client" or "server".
    * enum { server, client } ConnectionEnd;
    */
   tls.ConnectionEnd =
   {
      server: 0,
      client: 1
   };
   
   /**
    * Pseudo-random function algorithm used to generate keys from the
    * master secret.
    * enum { tls_prf_sha256 } PRFAlgorithm;
    */
   tls.PRFAlgorithm =
   {
      tls_prf_sha256: 0
   };
   
   /**
    * Bulk encryption algorithms.
    * enum { null, rc4, des3, aes } BulkCipherAlgorithm;
    */
   tls.BulkCipherAlgorithm =
   {
      none: null,
      rc4: 0,
      des3: 1,
      aes: 2
   };
   
   /**
    * Cipher types.
    * enum { stream, block, aead } CipherType;
    */
   tls.CipherType =
   {
      stream: 0,
      block: 1,
      aead: 2
   };
   
   /**
    * MAC (Message Authentication Code) algorithms.
    * enum { null, hmac_md5, hmac_sha1, hmac_sha256,
    *        hmac_sha384, hmac_sha512} MACAlgorithm;
    */
   tls.MACAlgorithm =
   {
      none: null,
      hmac_md5: 0,
      hmac_sha1: 1,
      hmac_sha256: 2,
      hmac_sha384: 3,
      hmac_sha512: 4
   };
   
   /**
    * Compression algorithms.
    * enum { null(0), deflate(1), (255) } CompressionMethod;
    */
   tls.CompressionMethod =
   {
      none: 0,
      deflate: 1
   };
   
   /**
    * TLS record content types.
    * enum {
    *    change_cipher_spec(20), alert(21), handshake(22),
    *    application_data(23), (255)
    * } ContentType;
    */
   tls.ContentType =
   {
      change_cipher_spec: 20,
      alert: 21,
      handshake: 22,
      application_data: 23
   };
   
   /**
    * TLS handshake types.
    * enum {
    *    hello_request(0), client_hello(1), server_hello(2),
    *    certificate(11), server_key_exchange (12),
    *    certificate_request(13), server_hello_done(14),
    *    certificate_verify(15), client_key_exchange(16),
    *    finished(20), (255)
    * } HandshakeType;
    */
   tls.HandshakeType =
   {
      hello_request: 0,
      client_hello: 1,
      server_hello: 2,
      certificate: 11,
      server_key_exchange: 12,
      certificate_request: 13,
      server_hello_done: 14,
      certificate_verify: 15,
      client_key_exchange: 16,
      finished: 20
   };
   
   /**
    * TLS Alert Protocol.
    * 
    * enum { warning(1), fatal(2), (255) } AlertLevel;
    * 
    * enum {
    *    close_notify(0),
    *    unexpected_message(10),
    *    bad_record_mac(20),
    *    decryption_failed(21),
    *    record_overflow(22),
    *    decompression_failure(30),
    *    handshake_failure(40),
    *    bad_certificate(42),
    *    unsupported_certificate(43),
    *    certificate_revoked(44),
    *    certificate_expired(45),
    *    certificate_unknown(46),
    *    illegal_parameter(47),
    *    unknown_ca(48),
    *    access_denied(49),
    *    decode_error(50),
    *    decrypt_error(51),
    *    export_restriction(60),
    *    protocol_version(70),
    *    insufficient_security(71),
    *    internal_error(80),
    *    user_canceled(90),
    *    no_renegotiation(100),
    *    (255)
    * } AlertDescription;
    *
    * struct {
    *    AlertLevel level;
    *    AlertDescription description;
    * } Alert;   
    */
   tls.Alert = {};
   tls.Alert.Level =
   {
      warning: 1,
      fatal: 2
   };
   tls.Alert.Description =
   {
      close_notify: 0,
      unexpected_message: 10,
      bad_record_mac: 20,
      decryption_failed: 21,
      record_overflow: 22,
      decompression_failure: 30,
      handshake_failure: 40,
      bad_certificate: 42,
      unsupported_certificate: 43,
      certificate_revoked: 44,
      certificate_expired: 45,
      certificate_unknown: 46,
      illegal_parameter: 47,
      unknown_ca: 48,
      access_denied: 49,
      decode_error: 50,
      decrypt_error: 51,
      export_restriction: 60,
      protocol_version: 70,
      insufficient_security: 71,
      internal_error: 80,
      user_canceled: 90,
      no_renegotiation: 100
   };
   
   /**
    * Supported cipher suites.
    */
   tls.CipherSuites =
   {
      TLS_RSA_WITH_AES_128_CBC_SHA: [0x00,0x2f],
      TLS_RSA_WITH_AES_256_CBC_SHA: [0x00,0x35]
   };
   
   /**
    * Gets a supported cipher suite from 2 bytes.
    * 
    * @param twoBytes two bytes in a string.
    * 
    * @return the matching supported cipher suite or null.
    */
   tls.getCipherSuite = function(twoBytes)
   {
      var rval = null;
      for(var key in tls.CipherSuites)
      {
         var cs = tls.CipherSuites[key];
         if(cs[0] === twoBytes.charCodeAt(0) &&
            cs[1] === twoBytes.charCodeAt(1))
         {
            rval = cs;
            break;
         }
      }
      return rval;
   };
   
   /**
    * Called when an unexpected record is encountered.
    * 
    * @param c the connection.
    * @param record the record.
    */
   tls.handleUnexpected = function(c, record)
   {
      c.error(c, {
         message: 'Unexpected message. Received TLS record out of order.',
         send: true,
         origin: 'client',
         alert: {
            level: tls.Alert.Level.fatal,
            description: tls.Alert.Description.unexpected_message
         }
      });
   };
   
   /**
    * Called when the client receives a HelloRequest record.
    * 
    * @param c the connection.
    * @param record the record.
    * @param length the length of the handshake message.
    */
   tls.handleHelloRequest = function(c, record, length)
   {
      // ignore renegotiation requests from the server during a handshake,
      // otherwise send a warning alert
      if(!c.handshakeState)
      {
         // send alert warning
         var record = tls.createAlert({
            level: tls.Alert.Level.warning,
            description: tls.Alert.Description.no_renegotiation
         });
         tls.queue(c, record);
         tls.flush(c);
      }
      
      // continue
      c.process();
   };
   
   /**
    * Called when the client receives a ServerHello record.
    * 
    * When this message will be sent:
    *    The server will send this message in response to a client hello
    *    message when it was able to find an acceptable set of algorithms.
    *    If it cannot find such a match, it will respond with a handshake
    *    failure alert.
    * 
    * uint24 length;
    * struct {
    *    ProtocolVersion server_version;
    *    Random random;
    *    SessionID session_id;
    *    CipherSuite cipher_suite;
    *    CompressionMethod compression_method;
    *    select(extensions_present) {
    *       case false:
    *          struct {};
    *       case true:
    *          Extension extensions<0..2^16-1>;
    *   };
    * } ServerHello;
    * 
    * @param c the connection.
    * @param record the record.
    * @param length the length of the handshake message.
    */
   tls.handleServerHello = function(c, record, length)
   {
      // minimum of 38 bytes in message
      if(length < 38)
      {
         c.error(c, {
            message: 'Invalid ServerHello message. Message too short.',
            send: true,
            origin: 'client',
            alert: {
               level: tls.Alert.Level.fatal,
               description: tls.Alert.Description.illegal_parameter
            }
         });
      }
      else
      {
         var b = record.fragment;
         var msg =
         {
            version:
            {
               major: b.getByte(),
               minor: b.getByte()
            },
            random: forge.util.createBuffer(b.getBytes(32)),
            session_id: readVector(b, 1),
            cipher_suite: b.getBytes(2),
            compression_method: b.getByte(),
            extensions: []
         };
         
         // read extensions if there are any
         if(b.length() > 0)
         {
            msg.extensions = readVector(b, 2);
         }
         
         // TODO: support other versions
         if(msg.version.major !== tls.Version.major ||
            msg.version.minor !== tls.Version.minor)
         {
            c.error(c, {
               message: 'Incompatible TLS version.',
               send: true,
               origin: 'client',
               alert: {
                  level: tls.Alert.Level.fatal,
                  description: tls.Alert.Description.protocol_version
               }
            });
         }
         
         // get the chosen cipher suite
         var cSuite = tls.getCipherSuite(msg.cipher_suite);
         
         // cipher suite not supported
         if(cSuite === null)
         {
            c.error(c, {
               message: 'Cipher suite not supported.',
               send: true,
               origin: 'client',
               alert: {
                  level: tls.Alert.Level.fatal,
                  description: tls.Alert.Description.handshake_failure
               },
               cipherSuite: forge.util.bytesToHex(msg.cipher_suite)
            });
         }
         
         if(!c.fail)
         {
            // see if the session ID is a match for session resumption,
            // an empty session ID indicates no resumption is supported
            var sid = forge.util.createBuffer(msg.session_id.bytes());
            sid = sid.getBytes();
            if(sid.length > 0 && sid === c.handshakeState.sessionId)
            {
               // resuming session, expect a ChangeCipherSpec next
               c.expect = SCC;
               c.handshakeState.resuming = true;
               
               // get security parameters from session and clear session
               c.handshakeState.sp = c.handshakeState.session.sp;
               c.handshakeState.session = null;
            }
            else
            {
               // not resuming, expect a server Certificate message next
               c.expect = SCE;
               c.handshakeState.resuming = false;
               
               /* Note: security params are from TLS 1.2, some values like
                  prf_algorithm are ignored for TLS 1.0 and the builtin as
                  specified in the spec is used.
                */
               
               // TODO: handle other options from server when more supported
               
               // only AES CBC is presently supported, so just change the key
               // length based on the chosen cipher suite
               var keyLength;
               switch(cSuite)
               {
                  case tls.CipherSuites.TLS_RSA_WITH_AES_128_CBC_SHA:
                     keyLength = 16;
                     break;
                  case tls.CipherSuites.TLS_RSA_WITH_AES_256_CBC_SHA:
                     keyLength = 32;
                     break;
               }
               
               // create new security parameters
               c.handshakeState.sp =
               {
                  entity: tls.ConnectionEnd.client,
                  prf_algorithm: tls.PRFAlgorithm.tls_prf_sha256,
                  bulk_cipher_algorithm: tls.BulkCipherAlgorithm.aes,
                  cipher_type: tls.CipherType.block,
                  enc_key_length: keyLength,
                  block_length: 16,
                  fixed_iv_length: 16,
                  record_iv_length: 16,
                  mac_algorithm: tls.MACAlgorithm.hmac_sha1,
                  mac_length: 20,
                  mac_key_length: 20,
                  compression_algorithm: msg.compression_method,
                  pre_master_secret: null,
                  master_secret: null,
                  client_random: null,
                  server_random: null
               };
            }
            
            // save client and server randoms
            c.handshakeState.sp.server_random = msg.random.bytes();
            c.handshakeState.sp.client_random = c.handshakeState.clientRandom;
            c.handshakeState.clientRandom = null;
            
            // set new session ID
            c.handshakeState.sessionId = sid;
            
            // continue
            c.process();
         }
      }
   };
   
   /**
    * Called when the client receives a Certificate record.
    * 
    * When this message will be sent:
    *    The server must send a certificate whenever the agreed-upon key
    *    exchange method is not an anonymous one. This message will always
    *    immediately follow the server hello message.
    *
    * Meaning of this message:
    *    The certificate type must be appropriate for the selected cipher
    *    suite's key exchange algorithm, and is generally an X.509v3
    *    certificate. It must contain a key which matches the key exchange
    *    method, as follows. Unless otherwise specified, the signing
    *    algorithm for the certificate must be the same as the algorithm
    *    for the certificate key. Unless otherwise specified, the public
    *    key may be of any length.
    * 
    * opaque ASN.1Cert<1..2^24-1>;
    * struct {
    *    ASN.1Cert certificate_list<1..2^24-1>;
    * } Certificate;
    * 
    * @param c the connection.
    * @param record the record.
    * @param length the length of the handshake message.
    */
   tls.handleCertificate = function(c, record, length)
   {
      // minimum of 3 bytes in message
      if(length < 3)
      {
         c.error(c, {
            message: 'Invalid Certificate message. Message too short.',
            send: true,
            origin: 'client',
            alert: {
               level: tls.Alert.Level.fatal,
               description: tls.Alert.Description.illegal_parameter
            }
         });
      }
      else
      {
         var b = record.fragment;
         var msg =
         {
            certificate_list: readVector(b, 3)
         };
         
         /* The sender's certificate will be first in the list (chain), each
            subsequent one that follows will certify the previous one, but
            root certificates (self-signed) that specify the certificate
            authority may be omitted under the assumption that the client must
            already possess it.
          */
         // each entry in msg.certificate_list is itself a vector with 3 length
         // bytes
         var cert, asn1;
         var certs = [];
         try
         {
            while(msg.certificate_list.length() > 0)
            {
               cert = readVector(msg.certificate_list, 3);
               asn1 = forge.asn1.fromDer(cert);
               cert = forge.pki.certificateFromAsn1(asn1, true);
               certs.push(cert);
            }
         }
         catch(ex)
         {
            c.error(c, {
               message: 'Could not parse certificate list.',
               cause: ex,
               send: true,
               origin: 'client',
               alert: {
                  level: tls.Alert.Level.fatal,
                  description: tls.Alert.Description.bad_certificate
               }
            });
         }
         
         if(!c.fail)
         {
            // ensure at least 1 certificate was provided
            if(certs.length === 0)
            {
               // error, no server certificate
               c.error(c, {
                  message: 'No server certificate provided.',
                  send: true,
                  origin: 'client',
                  alert: {
                     level: tls.Alert.Level.fatal,
                     description: tls.Alert.Description.illegal_parameter
                  }
               });
            }
            // check certificate chain
            else if(tls.verifyCertificateChain(c, certs))
            {
               // save server certificate handshake state
               c.handshakeState.serverCertificate = certs[0];
               
               // expect a ServerKeyExchange message next
               c.expect = SKE;
            }
            
            // continue
            c.process();
         }
      }
   };
   
   /**
    * Called when the client receives a ServerKeyExchange record.
    * 
    * When this message will be sent:
    *    This message will be sent immediately after the server
    *    certificate message (or the server hello message, if this is an
    *    anonymous negotiation).
    *
    *    The server key exchange message is sent by the server only when
    *    the server certificate message (if sent) does not contain enough
    *    data to allow the client to exchange a premaster secret.
    * 
    * Meaning of this message:
    *    This message conveys cryptographic information to allow the
    *    client to communicate the premaster secret: either an RSA public
    *    key to encrypt the premaster secret with, or a Diffie-Hellman
    *    public key with which the client can complete a key exchange
    *    (with the result being the premaster secret.)
    * 
    * enum {
    *    dhe_dss, dhe_rsa, dh_anon, rsa, dh_dss, dh_rsa
    * } KeyExchangeAlgorithm;
    * 
    * struct {
    *    opaque dh_p<1..2^16-1>;
    *    opaque dh_g<1..2^16-1>;
    *    opaque dh_Ys<1..2^16-1>;
    * } ServerDHParams;
    *
    * struct {
    *    select(KeyExchangeAlgorithm) {
    *       case dh_anon:
    *          ServerDHParams params;
    *       case dhe_dss:
    *       case dhe_rsa:
    *          ServerDHParams params;
    *          digitally-signed struct {
    *             opaque client_random[32];
    *             opaque server_random[32];
    *             ServerDHParams params;
    *          } signed_params;
    *       case rsa:
    *       case dh_dss:
    *       case dh_rsa:
    *          struct {};
    *    };
    * } ServerKeyExchange;
    * 
    * @param c the connection.
    * @param record the record.
    * @param length the length of the handshake message.
    */
   tls.handleServerKeyExchange = function(c, record, length)
   {
      // this implementation only supports RSA, no Diffie-Hellman support
      // so any length > 0 is invalid
      if(length > 0)
      {
         c.error(c, {
            message: 'Invalid key parameters. Only RSA is supported.',
            send: true,
            origin: 'client',
            alert: {
               level: tls.Alert.Level.fatal,
               description: tls.Alert.Description.unsupported_certificate
            }
         });
      }
      else
      {
         // expect an optional CertificateRequest message next
         c.expect = SCR;
         
         // continue
         c.process();
      }
   };
   
   /**
    * Called when the client receives a CertificateRequest record.
    * 
    * When this message will be sent:
    *    A non-anonymous server can optionally request a certificate from
    *    the client, if appropriate for the selected cipher suite. This
    *    message, if sent, will immediately follow the Server Key Exchange
    *    message (if it is sent; otherwise, the Server Certificate
    *    message).
    * 
    * enum {
    *    rsa_sign(1), dss_sign(2), rsa_fixed_dh(3), dss_fixed_dh(4),
    *    rsa_ephemeral_dh_RESERVED(5), dss_ephemeral_dh_RESERVED(6),
    *    fortezza_dms_RESERVED(20), (255)
    * } ClientCertificateType;
    * 
    * opaque DistinguishedName<1..2^16-1>;
    * 
    * struct {
    *    ClientCertificateType certificate_types<1..2^8-1>;
    *    SignatureAndHashAlgorithm supported_signature_algorithms<2^16-1>;
    *    DistinguishedName certificate_authorities<0..2^16-1>;
    * } CertificateRequest;
    * 
    * @param c the connection.
    * @param record the record.
    * @param length the length of the handshake message.
    */
   tls.handleCertificateRequest = function(c, record, length)
   {
      // minimum of 5 bytes in message
      if(length < 5)
      {
         c.error(c, {
            message: 'Invalid CertificateRequest. Message too short.',
            send: true,
            origin: 'client',
            alert: {
               level: tls.Alert.Level.fatal,
               description: tls.Alert.Description.illegal_parameter
            }
         });
      }
      else
      {
         // TODO: TLS 1.1 and 1.2 have different formats
         var b = record.fragment;
         var msg =
         {
            certificate_types: readVector(b, 1),
            certificate_authorities: readVector(b, 2)
         };
         
         // save certificate request
         c.handshakeState.certificateRequest = msg;
         
         // expect a ServerHelloDone message next
         c.expect = SHD;
         
         // continue
         c.process();
      }
   };
   
   /**
    * Called when the client receives a ServerHelloDone record.
    * 
    * When this message will be sent:
    *    The server hello done message is sent by the server to indicate
    *    the end of the server hello and associated messages. After
    *    sending this message the server will wait for a client response.
    *
    * Meaning of this message:
    *    This message means that the server is done sending messages to
    *    support the key exchange, and the client can proceed with its
    *    phase of the key exchange.
    *
    *    Upon receipt of the server hello done message the client should
    *    verify that the server provided a valid certificate if required
    *    and check that the server hello parameters are acceptable.
    * 
    * struct {} ServerHelloDone;
    * 
    * @param c the connection.
    * @param record the record.
    * @param length the length of the handshake message.
    */
   tls.handleServerHelloDone = function(c, record, length)
   {
      // len must be 0 bytes
      if(length > 0)
      {
         c.error(c, {
            message: 'Invalid ServerHelloDone message. Invalid length.',
            send: true,
            origin: 'client',
            alert: {
               level: tls.Alert.Level.fatal,
               description: tls.Alert.Description.record_overflow
            }
         });
      }
      // see if no server certificate was provided
      else if(c.serverCertificate === null)
      {
         var error = {
            message: 'No server certificate provided. Not enough security.',
            send: true,
            origin: 'client',
            alert: {
               level: tls.Alert.Level.fatal,
               description: tls.Alert.Description.insufficient_security
            }
         };
         
         // call application callback
         var ret = c.verify(c, error.alert.description, depth, []);
         if(ret === true)
         {
            // clear any set error
            error = null;
         }
         else
         {
            // check for custom alert info
            if(ret || ret === 0)
            {
               // set custom message and alert description
               if(ret.constructor == Object)
               {
                  if(ret.message)
                  {
                     error.message = ret.message;
                  }
                  if(ret.alert)
                  {
                     error.alert.description = ret.alert;
                  }
               }
               else if(ret.constructor == Number)
               {
                  // set custom alert description
                  error.alert.description = ret;
               }
            }
            
            // send error
            c.error(c, error);
         }
      }
      
      // create client certificate message if requested
      if(!c.fail && c.handshakeState.certificateRequest !== null)
      {
         record = tls.createRecord(
         {
            type: tls.ContentType.handshake,
            data: tls.createCertificate(c)
         });
         tls.queue(c, record);
      }
      
      if(!c.fail)
      {
         // create client key exchange message
         record = tls.createRecord(
         {
            type: tls.ContentType.handshake,
            data: tls.createClientKeyExchange(c)
         });
         tls.queue(c, record);
         
         // expect no messages until the following callback has been called
         c.expect = ERR;
         
         // create callback to handle client signature (for client-certs)
         var callback = function(c, signature)
         {
            var record = null;
            
            if(c.handshakeState.certificateRequest !== null)
            {
               // create certificate verify message
               record = tls.createRecord(
               {
                  type: tls.ContentType.handshake,
                  data: tls.createCertificateVerify(c, signature)
               });
               tls.queue(c, record);
            }
            
            // create change cipher spec message
            record = tls.createRecord(
            {
               type: tls.ContentType.change_cipher_spec,
               data: tls.createChangeCipherSpec()
            });
            tls.queue(c, record);
            
            // create pending state
            c.state.pending = tls.createConnectionState(c);
            
            // change current write state to pending write state
            c.state.current.write = c.state.pending.write;
            
            // create finished message
            record = tls.createRecord(
            {
               type: tls.ContentType.handshake,
               data: tls.createFinished(c)
            });
            tls.queue(c, record);
            
            // send records
            tls.flush(c);
            
            // expect a server ChangeCipherSpec message next
            c.expect = SCC;
            
            // continue
            c.process();
         };
         
         // if there is no certificate request, do callback immediately
         if(c.handshakeState.certificateRequest === null)
         {
            callback(c, null);
         }
         // otherwise get the client signature
         else
         {
            tls.getClientSignature(c, callback);
         }         
      }
   };
  
   /**
    * Called when the client receives a ChangeCipherSpec record.
    * 
    * @param c the connection.
    * @param record the record.
    */
   tls.handleChangeCipherSpec = function(c, record)
   {
      if(record.fragment.getByte() != 0x01)      
      {
         c.error(c, {
            message: 'Invalid ChangeCipherSpec message received.',
            send: true,
            origin: 'client',
            alert: {
               level: tls.Alert.Level.fatal,
               description: tls.Alert.Description.illegal_parameter
            }
         });
      }
      else
      {
         // create pending state if resuming session
         if(c.handshakeState.resuming)
         {
            c.state.pending = tls.createConnectionState(c);
         }
         
         // change current read state to pending read state
         c.state.current.read = c.state.pending.read;
         
         // clear pending state if not resuming session
         if(!c.handshakeState.resuming)
         {
            c.state.pending = null;
         }
         
         // expect a Finished record next
         c.expect = SFI;
         
         // continue
         c.process();
      }
   };
   
   /**
    * Called when the client receives a Finished record.
    * 
    * When this message will be sent:
    *    A finished message is always sent immediately after a change
    *    cipher spec message to verify that the key exchange and
    *    authentication processes were successful. It is essential that a
    *    change cipher spec message be received between the other
    *    handshake messages and the Finished message.
    *
    * Meaning of this message:
    *    The finished message is the first protected with the just-
    *    negotiated algorithms, keys, and secrets. Recipients of finished
    *    messages must verify that the contents are correct.  Once a side
    *    has sent its Finished message and received and validated the
    *    Finished message from its peer, it may begin to send and receive
    *    application data over the connection.
    * 
    * struct {
    *    opaque verify_data[verify_data_length];
    * } Finished;
    * 
    * verify_data
    *    PRF(master_secret, finished_label, Hash(handshake_messages))
    *       [0..verify_data_length-1];
    * 
    * finished_label
    *    For Finished messages sent by the client, the string
    *    "client finished". For Finished messages sent by the server, the
    *    string "server finished".
    * 
    * verify_data_length depends on the cipher suite. If it is not specified
    * by the cipher suite, then it is 12. Versions of TLS < 1.2 always used
    * 12 bytes.
    * 
    * @param c the connection.
    * @param record the record.
    * @param length the length of the handshake message.
    */
   tls.handleFinished = function(c, record, length)
   {
      // rewind to get full bytes for message so it can be manually
      // digested below (special case for Finished messages because they
      // must be digested *after* handling as opposed to all others)
      var b = record.fragment;
      b.read -= 4;
      var msgBytes = b.bytes();
      b.read += 4;
      
      // message contains only verify_data
      var vd = record.fragment.getBytes();
      
      // ensure verify data is correct
      b = forge.util.createBuffer();
      b.putBuffer(c.handshakeState.md5.digest());
      b.putBuffer(c.handshakeState.sha1.digest());
      
      // TODO: determine prf function and verify length for TLS 1.2
      var sp = c.handshakeState.sp;
      var vdl = 12;
      var prf = prf_TLS1;
      b = prf(sp.master_secret, 'server finished', b.getBytes(), vdl);
      if(b.getBytes() !== vd)
      {
         c.error(c, {
            message: 'Invalid verify_data in Finished message.',
            send: true,
            origin: 'client',
            alert: {
               level: tls.Alert.Level.fatal,
               description: tls.Alert.Description.decrypt_error
            }
         });
      }
      else
      {
         // digest finished message now that it has been handled
         c.handshakeState.md5.update(msgBytes);
         c.handshakeState.sha1.update(msgBytes);
         
         // resuming a session
         if(c.handshakeState.resuming)
         {
            // create change cipher spec message
            record = tls.createRecord(
            {
               type: tls.ContentType.change_cipher_spec,
               data: tls.createChangeCipherSpec()
            });
            tls.queue(c, record);
            
            // change current write state to pending write state
            c.state.current.write = c.state.pending.write;
            
            // clear pending state if resuming
            if(c.handshakeState.resuming)
            {
               c.state.pending = null;
            }
            
            // create finished message
            record = tls.createRecord(
            {
               type: tls.ContentType.handshake,
               data: tls.createFinished(c)
            });
            tls.queue(c, record);
            
            // send records
            tls.flush(c);
         }
         
         // expect server application data next
         c.expect = SAD;
         
         // now connected
         c.isConnected = true;
         c.connected(c);
         
         // continue
         c.process();
      }
   };
   
   /**
    * Called when the client receives an Alert record.
    * 
    * @param c the connection.
    * @param record the record.
    */
   tls.handleAlert = function(c, record)
   {
      // read alert
      var b = record.fragment;
      var alert =
      {
         level: b.getByte(),
         description: b.getByte()
      };
      
      // TODO: consider using a table?
      // get appropriate message
      var msg;
      switch(alert.description)
      {
         case tls.Alert.Description.close_notify:
            msg = 'Connection closed.';
            break;
         case tls.Alert.Description.unexpected_message:
            msg = 'Unexpected message.';
            break;
         case tls.Alert.Description.bad_record_mac:
            msg = 'Bad record MAC.';
            break;
         case tls.Alert.Description.decryption_failed:
            msg = 'Decryption failed.';
            break;
         case tls.Alert.Description.record_overflow:
            msg = 'Record overflow.';
            break;
         case tls.Alert.Description.decompression_failure:
            msg = 'Decompression failed.';
            break;
         case tls.Alert.Description.handshake_failure:
            msg = 'Handshake failure.';
            break;
         case tls.Alert.Description.bad_certificate:
            msg = 'Bad certificate.';
            break;
         case tls.Alert.Description.unsupported_certificate:
            msg = 'Unsupported certificate.';
            break;
         case tls.Alert.Description.certificate_revoked:
            msg = 'Certificate revoked.';
            break;
         case tls.Alert.Description.certificate_expired:
            msg = 'Certificate expired.';
            break;
         case tls.Alert.Description.certificate_unknown:
            msg = 'Certificate unknown.';
            break;
         case tls.Alert.Description.illegal_parameter:
            msg = 'Illegal parameter.';
            break;
         case tls.Alert.Description.unknown_ca:
            msg = 'Unknown certificate authority.';
            break;
         case tls.Alert.Description.access_denied:
            msg = 'Access denied.';
            break;
         case tls.Alert.Description.decode_error:
            msg = 'Decode error.';
            break;
         case tls.Alert.Description.decrypt_error:
            msg = 'Decrypt error.';
            break;
         case tls.Alert.Description.export_restriction:
            msg = 'Export restriction.';
            break;
         case tls.Alert.Description.protocol_version:
            msg = 'Unsupported protocol version.';
            break;
         case tls.Alert.Description.insufficient_security:
            msg = 'Insufficient security.';
            break;
         case tls.Alert.Description.internal_error:
            msg = 'Internal error.';
            break;
         case tls.Alert.Description.user_canceled:
            msg = 'User canceled.';
            break;
         case tls.Alert.Description.no_renegotiation:
            msg = 'Renegotiation not supported.';
            break;
         default:
            msg = 'Unknown error.';
            break;
      }
      
      // call error handler
      c.error(c, {
         message: msg,
         send: false,
         origin: 'server',
         alert: alert
      });
      
      // continue
      c.process();
   };
   
   /**
    * Called when the client receives a Handshake record.
    * 
    * @param c the connection.
    * @param record the record.
    */
   tls.handleHandshake = function(c, record)
   {
      // get the handshake type and message length
      var b = record.fragment;
      var type = b.getByte();
      var length = b.getInt24();
      
      // see if the record fragment doesn't yet contain the full message
      if(length > b.length())
      {
         // cache the record, clear its fragment, and reset the buffer read
         // pointer before the type and length were read
         c.fragmented = record;
         record.fragment = forge.util.createBuffer();
         b.read -= 4;
         
         // continue
         c.process();
      }
      else
      {
         // full message now available, clear cache, reset read pointer to
         // before type and length
         c.fragmented = null;
         b.read -= 4;
         
         // save the handshake bytes for digestion after handler is found
         // (include type and length of handshake msg)
         var bytes = b.bytes(length + 4);
         
         // restore read pointer
         b.read += 4;
         
         // handle expected message
         if(type in hsTable[c.expect])
         {
            /* Update handshake messages digest. The Finished message is not
               digested here it couldn't have been digested as part of the
               verify_data that is itself included in the Finished message.
               The message is manually digested in the Finished message
               handler. HelloRequest messages are simply never included in
               the handshake message digest according to spec.
             */
            if(type !== tls.HandshakeType.hello_request &&
               type !== tls.HandshakeType.finished)
            {
               c.handshakeState.md5.update(bytes);
               c.handshakeState.sha1.update(bytes);
            }
            
            // handle specific handshake type record
            hsTable[c.expect][type](c, record, length);
         }
         else
         {
            // unexpected record
            tls.handleUnexpected(c, record);
         }
      }
   };
   
   /**
    * Called when the client receives an ApplicationData record.
    * 
    * @param c the connection.
    * @param record the record.
    */
   tls.handleApplicationData = function(c, record)
   {
      // buffer data, notify that its ready
      c.data.putBuffer(record.fragment);
      c.dataReady(c);
      
      // continue
      c.process();
   };
   
   /**
    * The transistional state tables for receiving TLS records. It maps
    * the current TLS engine state and a received record to a function to
    * handle the record and update the state.
    * 
    * For instance, if the current state is SHE, then the TLS engine is
    * expecting a ServerHello record. Once a record is received, the handler
    * function is looked up using the state SHE and the record's content type.
    * 
    * The resulting function will either be an error handler or a record
    * handler. The function will take whatever action is appropriate and update
    * the state for the next record.
    * 
    * The states are all based on possible server record types. Note that the
    * client will never specifically expect to receive a HelloRequest or an
    * alert from the server so there is no state that reflects this. These
    * messages may occur at any time.
    * 
    * There are two tables for mapping states because there is a second tier
    * of types for handshake messages. Once a record with a content type of
    * handshake is received, the handshake record handler will look up the
    * handshake type in the secondary map to get its appropriate handler.
    * 
    * Valid message orders are as follows:
    *
    * =======================FULL HANDSHAKE======================
    * Client                                               Server
    * 
    * ClientHello                  -------->
    *                                                 ServerHello
    *                                                Certificate*
    *                                          ServerKeyExchange*
    *                                         CertificateRequest*
    *                              <--------      ServerHelloDone
    * Certificate*
    * ClientKeyExchange
    * CertificateVerify*
    * [ChangeCipherSpec]
    * Finished                     -------->
    *                                          [ChangeCipherSpec]
    *                              <--------             Finished
    * Application Data             <------->     Application Data
    * 
    * =====================SESSION RESUMPTION=====================
    * Client                                                Server
    *
    * ClientHello                   -------->
    *                                                  ServerHello
    *                                           [ChangeCipherSpec]
    *                               <--------             Finished
    * [ChangeCipherSpec]
    * Finished                      -------->
    * Application Data              <------->     Application Data   
    */
   // expect states (indicate which records are expected to be received)
   var SHE = 0; // rcv server hello
   var SCE = 1; // rcv server certificate
   var SKE = 2; // rcv server key exchange
   var SCR = 3; // rcv certificate request
   var SHD = 4; // rcv server hello done
   var SCC = 5; // rcv change cipher spec
   var SFI = 6; // rcv finished
   var SAD = 7; // rcv application data
   var ERR = 8; // not expecting any messages at this point
   
   // map current expect state and content type to function
   var __ = tls.handleUnexpected;
   var F0 = tls.handleChangeCipherSpec;
   var F1 = tls.handleAlert;
   var F2 = tls.handleHandshake;
   var F3 = tls.handleApplicationData;
   var ctTable = [
   //      CC,AL,HS,AD
   /*SHE*/[__,__,F2,__],
   /*SCE*/[__,F1,F2,__],
   /*SKE*/[__,F1,F2,__],
   /*SCR*/[__,F1,F2,__],
   /*SHD*/[__,F1,F2,__],
   /*SCC*/[F0,F1,__,__],
   /*SFI*/[__,F1,F2,__],
   /*SAD*/[__,F1,F2,F3],
   /*ERR*/[__,F1,F2,__]
   ];
   
   // map current expect state and handshake type to function
   var F4 = tls.handleHelloRequest;
   var F5 = tls.handleServerHello;
   var F6 = tls.handleCertificate;
   var F7 = tls.handleServerKeyExchange;
   var F8 = tls.handleCertificateRequest;
   var F9 = tls.handleServerHelloDone;
   var FA = tls.handleCertificateVerify;
   var FB = tls.handleFinished;
   var hsTable = [
   //      HR,01,SH,03,04,05,06,07,08,09,10,SC,SK,CR,HD,CV,CK,17,18,19,FI
   /*SHE*/[__,__,F5,__,__,__,__,__,__,__,__,__,__,__,__,__,__,__,__,__,__],
   /*SCE*/[F4,__,__,__,__,__,__,__,__,__,__,F6,F7,F8,F9,__,__,__,__,__,__],
   /*SKE*/[F4,__,__,__,__,__,__,__,__,__,__,__,F7,F8,F9,__,__,__,__,__,__],
   /*SCR*/[F4,__,__,__,__,__,__,__,__,__,__,__,__,F8,F9,__,__,__,__,__,__],
   /*SHD*/[F4,__,__,__,__,__,__,__,__,__,__,__,__,__,F9,__,__,__,__,__,__],
   /*SCC*/[F4,__,__,__,__,__,__,__,__,__,__,__,__,__,__,__,__,__,__,__,__],
   /*SFI*/[F4,__,__,__,__,__,__,__,__,__,__,__,__,__,__,__,__,__,__,__,FB],
   /*SAD*/[F4,__,__,__,__,__,__,__,__,__,__,__,__,__,__,__,__,__,__,__,__],
   /*ERR*/[F4,__,__,__,__,__,__,__,__,__,__,__,__,__,__,__,__,__,__,__,__]
   ];
   
   /**
    * Generates the master_secret and keys using the given security parameters.
    * 
    * The security parameters for a TLS connection state are defined as
    * such:
    * 
    * struct {
    *    ConnectionEnd          entity;
    *    PRFAlgorithm           prf_algorithm;
    *    BulkCipherAlgorithm    bulk_cipher_algorithm;
    *    CipherType             cipher_type;
    *    uint8                  enc_key_length;
    *    uint8                  block_length;
    *    uint8                  fixed_iv_length;
    *    uint8                  record_iv_length;
    *    MACAlgorithm           mac_algorithm;
    *    uint8                  mac_length;
    *    uint8                  mac_key_length;
    *    CompressionMethod      compression_algorithm;
    *    opaque                 master_secret[48];
    *    opaque                 client_random[32]; 
    *    opaque                 server_random[32];
    * } SecurityParameters;
    * 
    * Note that this definition is from TLS 1.2. In TLS 1.0 some of these
    * parameters are ignored because, for instance, the PRFAlgorithm is a
    * builtin-fixed algorithm combining iterations of MD5 and SHA-1 in
    * TLS 1.0.
    * 
    * The Record Protocol requires an algorithm to generate keys required
    * by the current connection state.
    * 
    * The master secret is expanded into a sequence of secure bytes, which
    * is then split to a client write MAC key, a server write MAC key, a
    * client write encryption key, and a server write encryption key. In TLS
    * 1.0 a client write IV and server write IV are also generated. Each
    * of these is generated from the byte sequence in that order. Unused
    * values are empty. In TLS 1.2, some AEAD ciphers may additionally require
    * a client write IV and a server write IV (see Section 6.2.3.3).
    *
    * When keys, MAC keys, and IVs are generated, the master secret is used as
    * an entropy source.
    *
    * To generate the key material, compute:
    * 
    * master_secret = PRF(pre_master_secret, "master secret",
    *                     ClientHello.random + ServerHello.random)
    *
    * key_block = PRF(SecurityParameters.master_secret,
    *                 "key expansion",
    *                 SecurityParameters.server_random +
    *                 SecurityParameters.client_random);
    *
    * until enough output has been generated. Then, the key_block is
    * partitioned as follows:
    *
    * client_write_MAC_key[SecurityParameters.mac_key_length]
    * server_write_MAC_key[SecurityParameters.mac_key_length]
    * client_write_key[SecurityParameters.enc_key_length]
    * server_write_key[SecurityParameters.enc_key_length]
    * client_write_IV[SecurityParameters.fixed_iv_length]
    * server_write_IV[SecurityParameters.fixed_iv_length]
    *
    * In TLS 1.2, the client_write_IV and server_write_IV are only generated
    * for implicit nonce techniques as described in Section 3.2.1 of
    * [AEAD]. This implementation uses TLS 1.0 so IVs are generated.
    *
    * Implementation note: The currently defined cipher suite which
    * requires the most material is AES_256_CBC_SHA256. It requires 2 x 32
    * byte keys and 2 x 32 byte MAC keys, for a total 128 bytes of key
    * material. In TLS 1.0 it also requires 2 x 16 byte IVs, so it actually
    * takes 160 bytes of key material.
    * 
    * @param c the connection.
    * @param sp the security parameters to use.
    * 
    * @return the security keys.
    */
   tls.generateKeys = function(c, sp)
   {
      // TLS_RSA_WITH_AES_128_CBC_SHA (required to be compliant with TLS 1.2) &
      // TLS_RSA_WITH_AES_128_CBC_SHA are the only cipher suites implemented
      // at present
      
      // TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA is required to be compliant with
      // TLS 1.0 but we don't care right now because AES is better and we have
      // an implementation for it
      
      // TODO: TLS 1.2 implementation
      /*
      // determine the PRF
      var prf;
      switch(sp.prf_algorithm)
      {
         case tls.PRFAlgorithm.tls_prf_sha256:
            prf = prf_sha256;
            break;
         default:
            // should never happen
            throw {
               message: 'Invalid PRF'
            };
            break;
      }
      
      // concatenate client and server random
      var random = sp.client_random + sp.server_random;
      
      // only create master secret if session is new
      if(!c.handshakeState.resuming)
      {
         // create master secret, clean up pre-master secret
         sp.master_secret =
            prf(sp.pre_master_secret, 'master secret', random, 48).bytes();
         sp.pre_master_secret = null;
      }
      
      // generate the amount of key material needed
      random = sp.server_random + sp.client_random;
      var length = 2 * sp.mac_key_length + 2 * sp.enc_key_length;
      var km = prf(sp.master_secret.bytes(), 'key expansion', random, length);
      
      // split the key material into the MAC and encryption keys
      return {
         client_write_MAC_key: km.getBytes(sp.mac_key_length),
         server_write_MAC_key: km.getBytes(sp.mac_key_length),
         client_write_key: km.getBytes(sp.enc_key_length),
         server_write_key: km.getBytes(sp.enc_key_length)
      };
      */
      
      // TLS 1.0 implementation
      var prf = prf_TLS1;
      
      // concatenate server and client random
      var random = sp.client_random + sp.server_random;
      
      // only create master secret if session is new
      if(!c.handshakeState.resuming)
      {
         // create master secret, clean up pre-master secret
         sp.master_secret =
            prf(sp.pre_master_secret, 'master secret', random, 48).bytes();
         sp.pre_master_secret = null;
      }
      
      // generate the amount of key material needed
      random = sp.server_random + sp.client_random;
      var length =
         2 * sp.mac_key_length +
         2 * sp.enc_key_length +
         2 * sp.fixed_iv_length;
      var km = prf(sp.master_secret, 'key expansion', random, length);
      
      // split the key material into the MAC and encryption keys
      return {
         client_write_MAC_key: km.getBytes(sp.mac_key_length),
         server_write_MAC_key: km.getBytes(sp.mac_key_length),
         client_write_key: km.getBytes(sp.enc_key_length),
         server_write_key: km.getBytes(sp.enc_key_length),
         client_write_IV: km.getBytes(sp.fixed_iv_length),
         server_write_IV: km.getBytes(sp.fixed_iv_length)
      };
   };

   /**
    * Creates a new initialized TLS connection state. A connection state has
    * a read mode and a write mode.
    * 
    * compression state:
    *    The current state of the compression algorithm.
    * 
    * cipher state:
    *    The current state of the encryption algorithm. This will consist of
    *    the scheduled key for that connection. For stream ciphers, this
    *    will also contain whatever state information is necessary to allow
    *    the stream to continue to encrypt or decrypt data.
    * 
    * MAC key:
    *    The MAC key for the connection.
    * 
    * sequence number:
    *    Each connection state contains a sequence number, which is
    *    maintained separately for read and write states. The sequence
    *    number MUST be set to zero whenever a connection state is made the
    *    active state. Sequence numbers are of type uint64 and may not
    *    exceed 2^64-1.  Sequence numbers do not wrap. If a TLS
    *    implementation would need to wrap a sequence number, it must
    *    renegotiate instead. A sequence number is incremented after each
    *    record: specifically, the first record transmitted under a
    *    particular connection state MUST use sequence number 0.
    * 
    * @param c the connection.
    * 
    * @return the new initialized TLS connection state.
    */
   tls.createConnectionState = function(c)
   {
      var createMode = function()
      {
         var mode =
         {
            // two 32-bit numbers, first is most significant
            sequenceNumber: [0, 0],
            macKey: null,
            macLength: 0,
            macFunction: null,
            cipherState: null,
            cipherFunction: function(record){return true;},
            compressionState: null,
            compressFunction: function(record){return true;},
            updateSequenceNumber: function()
            {
               if(mode.sequenceNumber[1] == 0xFFFFFFFF)
               {
                  mode.sequenceNumber[1] = 0;
                  ++mode.sequenceNumber[0];
               }
               else
               {
                  ++mode.sequenceNumber[1];
               }
            }
         };
         return mode;
      };
      var state =
      {
         read: createMode(),
         write: createMode()
      };
      
      // update function in read mode will decrypt then decompress a record
      state.read.update = function(c, record)
      {
         if(!state.read.cipherFunction(record, state.read))
         {
            c.error(c, {
               message: 'Could not decrypt record or bad MAC.',
               send: true,
               origin: 'client',
               alert: {
                  level: tls.Alert.Level.fatal,
                  // doesn't matter if decryption failed or MAC was
                  // invalid, return the same error so as not to reveal
                  // which one occurred
                  description: tls.Alert.Description.bad_record_mac
               }
            });
         }
         else if(!state.read.compressFunction(c, record, state.read))
         {
            c.error(c, {
               message: 'Could not decompress record.',
               send: true,
               origin: 'client',
               alert: {
                  level: tls.Alert.Level.fatal,
                  description: tls.Alert.Description.decompression_failure
               }
            });
         }
         return !c.fail;
      };
      
      // update function in write mode will compress then encrypt a record
      state.write.update = function(c, record)
      {
         if(!state.write.compressFunction(c, record, state.write))
         {
            // error, but do not send alert since it would require
            // compression as well
            c.error(c, {
               message: 'Could not compress record.',
               send: false,
               origin: 'client',
               alert: {
                  level: tls.Alert.Level.fatal,
                  description: tls.Alert.Description.internal_error
               }
            });
         }
         else if(!state.write.cipherFunction(record, state.write))
         {
            // error, but do not send alert since it would require
            // encryption as well
            c.error(c, {
               message: 'Could not encrypt record.',
               send: false,
               origin: 'client',
               alert: {
                  level: tls.Alert.Level.fatal,
                  description: tls.Alert.Description.internal_error
               }
            });
         }
         return !c.fail;
      };
      
      // handle security parameters
      if(c.handshakeState)
      {
         // generate keys
         var sp = c.handshakeState.sp;
         sp.keys = tls.generateKeys(c, sp);
         
         // mac setup
         state.read.macKey = sp.keys.server_write_MAC_key;
         state.write.macKey = sp.keys.client_write_MAC_key;
         state.read.macLength = state.write.macLength = sp.mac_length;
         switch(sp.mac_algorithm)
         {
            case tls.MACAlgorithm.hmac_sha1:
               state.read.macFunction = state.write.macFunction = hmac_sha1;
               break;
             default:
                throw {
                   message: 'Unsupported MAC algorithm'
                };
         }
         
         // cipher setup
         switch(sp.bulk_cipher_algorithm)
         {
            case tls.BulkCipherAlgorithm.aes:
               state.read.cipherState =
               {
                  init: false,
                  cipher: forge.aes.createDecryptionCipher(
                     sp.keys.server_write_key),
                  iv: sp.keys.server_write_IV
               };
               state.write.cipherState =
               {
                  init: false,
                  cipher: forge.aes.createEncryptionCipher(
                     sp.keys.client_write_key),
                  iv: sp.keys.client_write_IV
               };
               state.read.cipherFunction = decrypt_aes_128_cbc_sha1;
               state.write.cipherFunction = encrypt_aes_128_cbc_sha1;
               break;
            default:
               throw {
                  message: 'Unsupported cipher algorithm'
               };
         }
         switch(sp.cipher_type)
         {
            case tls.CipherType.block:
               break;
            default:
               throw {
                  message: 'Unsupported cipher type'
               };
         }
         
         // compression setup
         switch(sp.compression_algorithm)
         {
            case tls.CompressionMethod.none:
               break;
            case tls.CompressionMethod.deflate:
               state.read.compressFunction = inflate;
               state.write.compressFunction = deflate;
               break;
            default:
               throw {
                  message: 'Unsupported compression algorithm'
               };
         }
      }
      
      return state;
   };
   
   /**
    * Creates a Random structure.
    * 
    * struct {
    *    uint32 gmt_unix_time;
    *    opaque random_bytes[28];
    * } Random;
    * 
    * gmt_unix_time:
    *    The current time and date in standard UNIX 32-bit format
    *    (seconds since the midnight starting Jan 1, 1970, UTC, ignoring
    *    leap seconds) according to the sender's internal clock. Clocks
    *    are not required to be set correctly by the basic TLS protocol;
    *    higher-level or application protocols may define additional
    *    requirements. Note that, for historical reasons, the data
    *    element is named using GMT, the predecessor of the current
    *    worldwide time base, UTC.
    * random_bytes:
    *    28 bytes generated by a secure random number generator.
    * 
    * @return the Random structure as a byte array.
    */
   tls.createRandom = function()
   {
      // get UTC milliseconds
      var d = new Date();
      var utc = +d + d.getTimezoneOffset() * 60000;
      var rval = forge.util.createBuffer();
      rval.putInt32(utc);
      rval.putBytes(forge.random.getBytes(28));
      return rval;
   };
   
   /**
    * Creates a TLS record with the given type and data.
    * 
    * @param options:
    *    type: the record type.
    *    data: the plain text data in a byte buffer.
    * 
    * @return the created record.
    */
   tls.createRecord = function(options)
   {
      var record =
      {
         type: options.type,
         version:
         {
            major: tls.Version.major,
            minor: tls.Version.minor
         },
         length: options.data.length(),
         fragment: options.data
      };
      return record;
   };
   
   /**
    * Creates a TLS alert record.
    * 
    * @param alert:
    *    level: the TLS alert level.
    *    description: the TLS alert description.
    * 
    * @return the created alert record.
    */
   tls.createAlert = function(alert)
   {
      var b = forge.util.createBuffer();
      b.putByte(alert.level);
      b.putByte(alert.description);
      return tls.createRecord({
         type: tls.ContentType.alert,
         data: b
      });
   };
   
   /* The structure of a TLS handshake message.
    * 
    * struct {
    *    HandshakeType msg_type;    // handshake type
    *    uint24 length;             // bytes in message
    *    select(HandshakeType) {
    *       case hello_request:       HelloRequest;
    *       case client_hello:        ClientHello;
    *       case server_hello:        ServerHello;
    *       case certificate:         Certificate;
    *       case server_key_exchange: ServerKeyExchange;
    *       case certificate_request: CertificateRequest;
    *       case server_hello_done:   ServerHelloDone;
    *       case certificate_verify:  CertificateVerify;
    *       case client_key_exchange: ClientKeyExchange;
    *       case finished:            Finished;
    *    } body;
    * } Handshake;
    */
   
   /**
    * Creates a ClientHello message.
    * 
    * opaque SessionID<0..32>;
    * enum { null(0), deflate(1), (255) } CompressionMethod;
    * uint8 CipherSuite[2];
    * 
    * struct {
    *    ProtocolVersion client_version;
    *    Random random;
    *    SessionID session_id;
    *    CipherSuite cipher_suites<2..2^16-2>;
    *    CompressionMethod compression_methods<1..2^8-1>;
    *    select(extensions_present) {
    *        case false:
    *            struct {};
    *        case true:
    *            Extension extensions<0..2^16-1>;
    *    };
    * } ClientHello;
    * 
    * The extension format for extended client hellos and extended server
    * hellos is:
    * 
    * struct {
    *    ExtensionType extension_type;
    *    opaque extension_data<0..2^16-1>;
    * } Extension;
    * 
    * Here:
    * 
    * - "extension_type" identifies the particular extension type.
    * - "extension_data" contains information specific to the particular
    * extension type.
    * 
    * The extension types defined in this document are:
    * 
    * enum {
    *    server_name(0), max_fragment_length(1),
    *    client_certificate_url(2), trusted_ca_keys(3),
    *    truncated_hmac(4), status_request(5), (65535)
    * } ExtensionType;
    * 
    * @param c the connection.
    * @param sessionId the session ID to use.
    * @param random the client random structure to use.
    * 
    * @return the ClientHello byte buffer.
    */
   tls.createClientHello = function(c, sessionId, random)
   {
      // create supported cipher suites
      var cipherSuites = forge.util.createBuffer();
      for(var i = 0; i < c.cipherSuites.length; ++i)
      {
         var cs = c.cipherSuites[i];
         cipherSuites.putByte(cs[0]);
         cipherSuites.putByte(cs[1]);
      }
      var cSuites = cipherSuites.length();
      
      // create supported compression methods, null always supported, but
      // also support deflate if connection has inflate and deflate methods
      var compressionMethods = forge.util.createBuffer();
      compressionMethods.putByte(0x00); // null method
      // FIXME: deflate support disabled until issues with raw deflate data
      // without zlib headers are resolved
      /*
      if(c.inflate !== null && c.deflate !== null)
      {
         compressionMethods.putByte(0x01); // deflate method
      }
      */
      var cMethods = compressionMethods.length();
      
      // create TLS SNI (server name indication) extension if virtual host
      // has been specified, see RFC 3546
      var extensions = forge.util.createBuffer();
      if(c.virtualHost)
      {
         // create extension struct
         var ext = forge.util.createBuffer();
         ext.putByte(0x00); // type server_name (ExtensionType is 2 bytes)
         ext.putByte(0x00);
         
         /* In order to provide the server name, clients MAY include an
          * extension of type "server_name" in the (extended) client hello.
          * The "extension_data" field of this extension SHALL contain
          * "ServerNameList" where:
          * 
          * struct {
          *    NameType name_type;
          *    select(name_type) {
          *       case host_name: HostName;
          *    } name;
          * } ServerName;
          * 
          * enum {
          *    host_name(0), (255)
          * } NameType;
          * 
          * opaque HostName<1..2^16-1>;
          * 
          * struct {
          *    ServerName server_name_list<1..2^16-1>
          * } ServerNameList;
          */
         var serverName = forge.util.createBuffer();
         serverName.putByte(0x00); // type host_name
         writeVector(serverName, 2, forge.util.createBuffer(c.virtualHost));
         
         // ServerNameList is in extension_data
         var snList = forge.util.createBuffer();
         writeVector(snList, 2, serverName);
         writeVector(ext, 2, snList);
         extensions.putBuffer(ext);
      }
      var extLength = extensions.length();
      if(extLength > 0)
      {
         // add extension vector length
         extLength += 2;
      }
      
      // determine length of the handshake message
      // cipher suites and compression methods size will need to be
      // updated if more get added to the list
      var length =
         sessionId.length + 1 + // session ID vector
         2 +                    // version (major + minor)
         4 + 28 +               // random time and random bytes
         2 + cSuites +          // cipher suites vector
         1 + cMethods +         // compression methods vector
         extLength;             // extensions vector
      
      // build record fragment
      var rval = forge.util.createBuffer();
      rval.putByte(tls.HandshakeType.client_hello);
      rval.putInt24(length);               // handshake length
      rval.putByte(tls.Version.major);     // major version
      rval.putByte(tls.Version.minor);     // minor version
      rval.putBytes(random.bytes());       // random time + bytes
      writeVector(rval, 1, forge.util.createBuffer(sessionId));
      writeVector(rval, 2, cipherSuites);
      writeVector(rval, 1, compressionMethods);
      if(extLength > 0)
      {
         writeVector(rval, 2, extensions);
      }
      return rval;
   };
   
   /**
    * Creates a Certificate message.
    * 
    * When this message will be sent:
    *    This is the first message the client can send after receiving a
    *    server hello done message. This message is only sent if the
    *    server requests a certificate. If no suitable certificate is
    *    available, the client should send a certificate message
    *    containing no certificates. If client authentication is required
    *    by the server for the handshake to continue, it may respond with
    *    a fatal handshake failure alert.
    * 
    * opaque ASN.1Cert<1..2^24-1>;
    *
    * struct {
    *     ASN.1Cert certificate_list<0..2^24-1>;
    * } Certificate;
    * 
    * @param c the connection.
    * 
    * @return the Certificate byte buffer.
    */
   tls.createCertificate = function(c)
   {
      // TODO: support sending more than 1 certificate?
      // TODO: check certificate request to ensure types are supported
      
      // get a client-side certificate (a certificate as a PEM string)
      var cert = null;
      if(c.getCertificate)
      {
         cert = c.getCertificate(c, c.handshakeState.certificateRequest);
      }
      
      // buffer to hold client-side cert
      var certBuffer = forge.util.createBuffer();
      if(cert !== null)
      {
         try
         {
            // certificate entry is itself a vector with 3 length bytes
            var der = forge.pki.pemToDer(cert);
            var asn1 = forge.asn1.fromDer(der.bytes());
            writeVector(certBuffer, 3, der);
            
            // save certificate
            c.handshakeState.certificate = forge.pki.certificateFromAsn1(asn1);
         }
         catch(ex)
         {
            c.error(c, {
               message: 'Could not send certificate list.',
               cause: ex,
               send: true,
               origin: 'client',
               alert: {
                  level: tls.Alert.Level.fatal,
                  description: tls.Alert.Description.bad_certificate
               }
            });
         }
      }
      
      // determine length of the handshake message
      var length = 3 + certBuffer.length(); // cert vector
      
      // build record fragment
      var rval = forge.util.createBuffer();
      rval.putByte(tls.HandshakeType.certificate);
      rval.putInt24(length);
      writeVector(rval, 3, certBuffer);
      return rval;
   };
   
   /**
    * Creates a ClientKeyExchange message.
    * 
    * When this message will be sent:
    *    This message is always sent by the client. It will immediately
    *    follow the client certificate message, if it is sent. Otherwise
    *    it will be the first message sent by the client after it receives
    *    the server hello done message.
    *
    * Meaning of this message:
    *    With this message, the premaster secret is set, either though
    *    direct transmission of the RSA-encrypted secret, or by the
    *    transmission of Diffie-Hellman parameters which will allow each
    *    side to agree upon the same premaster secret. When the key
    *    exchange method is DH_RSA or DH_DSS, client certification has
    *    been requested, and the client was able to respond with a
    *    certificate which contained a Diffie-Hellman public key whose
    *    parameters (group and generator) matched those specified by the
    *    server in its certificate, this message will not contain any
    *    data.
    * 
    * Meaning of this message:
    *    If RSA is being used for key agreement and authentication, the
    *    client generates a 48-byte premaster secret, encrypts it using
    *    the public key from the server's certificate or the temporary RSA
    *    key provided in a server key exchange message, and sends the
    *    result in an encrypted premaster secret message. This structure
    *    is a variant of the client key exchange message, not a message in
    *    itself.
    * 
    * struct {
    *    select(KeyExchangeAlgorithm) {
    *       case rsa: EncryptedPreMasterSecret;
    *       case diffie_hellman: ClientDiffieHellmanPublic;
    *    } exchange_keys;
    * } ClientKeyExchange;
    * 
    * struct {
    *    ProtocolVersion client_version;
    *    opaque random[46];
    * } PreMasterSecret;
    *
    * struct {
    *    public-key-encrypted PreMasterSecret pre_master_secret;
    * } EncryptedPreMasterSecret;
    * 
    * A public-key-encrypted element is encoded as a vector <0..2^16-1>.
    * 
    * @param c the connection.
    * 
    * @return the ClientKeyExchange byte buffer.
    */
   tls.createClientKeyExchange = function(c)
   {
      // create buffer to encrypt
      var b = forge.util.createBuffer();
      
      // add highest client-supported protocol to help server avoid version
      // rollback attacks
      b.putByte(tls.Version.major);
      b.putByte(tls.Version.minor);
      
      // generate and add 46 random bytes
      b.putBytes(forge.random.getBytes(46));
      
      // save pre-master secret
      var sp = c.handshakeState.sp;
      sp.pre_master_secret = b.getBytes();
      
      // RSA-encrypt the pre-master secret
      var key = c.handshakeState.serverCertificate.publicKey;
      b = key.encrypt(sp.pre_master_secret);
      
      /* Note: The encrypted pre-master secret will be stored in a
         public-key-encrypted opaque vector that has the length prefixed
         using 2 bytes, so include those 2 bytes in the handshake message
         length. This is done as a minor optimization instead of calling
         writeVector().
       */
      
      // determine length of the handshake message
      var length = b.length + 2;
      
      // build record fragment
      var rval = forge.util.createBuffer();
      rval.putByte(tls.HandshakeType.client_key_exchange);
      rval.putInt24(length);
      // add vector length bytes
      rval.putInt16(b.length);
      rval.putBytes(b);
      return rval;
   };
   
   /**
    * Gets the signed data used to verify a client-side certificate. See
    * tls.createCertificateVerify() for details.
    * 
    * @param c the connection.
    * @param callback the callback to call once the signed data is ready.
    */
   tls.getClientSignature = function(c, callback)
   {
      // generate data to RSA encrypt
      var b = forge.util.createBuffer();
      b.putBuffer(c.handshakeState.md5.digest());
      b.putBuffer(c.handshakeState.sha1.digest());
      b = b.getBytes();
      
      // create default signing function as necessary
      c.getSignature = c.getSignature || function(c, b, callback)
      {
         // do rsa encryption, call callback
         var privateKey = null;
         if(c.getPrivateKey)
         {
            try
            {
               privateKey = c.getPrivateKey(c, c.handshakeState.certificate);
               privateKey = forge.pki.privateKeyFromPem(privateKey);
            }
            catch(ex)
            {
               c.error(c, {
                  message: 'Could not get private key.',
                  cause: ex,
                  send: true,
                  origin: 'client',
                  alert: {
                     level: tls.Alert.Level.fatal,
                     description: tls.Alert.Description.internal_error
                  }
               });
            }
         }
         b = forge.pki.rsa.encrypt(b, privateKey, 0x01);
         callback(c, b);
      };
      
      // get client signature
      c.getSignature(c, b, callback);
   };
   
   /**
    * Creates a CertificateVerify message.
    * 
    * Meaning of this message:
    *    This structure conveys the client's Diffie-Hellman public value
    *    (Yc) if it was not already included in the client's certificate.
    *    The encoding used for Yc is determined by the enumerated
    *    PublicValueEncoding. This structure is a variant of the client
    *    key exchange message, not a message in itself.
    *   
    * When this message will be sent:
    *    This message is used to provide explicit verification of a client
    *    certificate. This message is only sent following a client
    *    certificate that has signing capability (i.e. all certificates
    *    except those containing fixed Diffie-Hellman parameters). When
    *    sent, it will immediately follow the client key exchange message.
    * 
    * struct {
    *    Signature signature;
    * } CertificateVerify;
    *   
    * CertificateVerify.signature.md5_hash
    *    MD5(handshake_messages);
    *
    * Certificate.signature.sha_hash
    *    SHA(handshake_messages);
    *
    * Here handshake_messages refers to all handshake messages sent or
    * received starting at client hello up to but not including this
    * message, including the type and length fields of the handshake
    * messages.
    * 
    * select(SignatureAlgorithm) {
    *    case anonymous: struct { };
    *    case rsa:
    *       digitally-signed struct {
    *          opaque md5_hash[16];
    *          opaque sha_hash[20];
    *       };
    *    case dsa:
    *       digitally-signed struct {
    *          opaque sha_hash[20];
    *       };
    * } Signature;
    * 
    * In digital signing, one-way hash functions are used as input for a
    * signing algorithm. A digitally-signed element is encoded as an opaque
    * vector <0..2^16-1>, where the length is specified by the signing
    * algorithm and key.
    *
    * In RSA signing, a 36-byte structure of two hashes (one SHA and one
    * MD5) is signed (encrypted with the private key). It is encoded with
    * PKCS #1 block type 0 or type 1 as described in [PKCS1].
    * 
    * In DSS, the 20 bytes of the SHA hash are run directly through the
    * Digital Signing Algorithm with no additional hashing.
    * 
    * @param c the connection.
    * @param signature the signature to include in the message.
    * 
    * @return the CertificateVerify byte buffer.
    */
   tls.createCertificateVerify = function(c, signature)
   {
      /* Note: The signature will be stored in as digitally-signed opaque
         vector that has the length prefixed using 2 bytes, so include those
         2 bytes in the handshake message length. This is done as a minor
         optimization instead of calling writeVector().
       */
      
      // determine length of the handshake message
      var length = signature.length + 2;
      
      // build record fragment
      var rval = forge.util.createBuffer();
      rval.putByte(tls.HandshakeType.certificate_verify);
      rval.putInt24(length);
      // add vector length bytes
      rval.putInt16(signature.length);
      rval.putBytes(signature);
      return rval;
   };
   
   /**
    * Creates a ChangeCipherSpec message.
    * 
    * The change cipher spec protocol exists to signal transitions in
    * ciphering strategies. The protocol consists of a single message,
    * which is encrypted and compressed under the current (not the pending)
    * connection state. The message consists of a single byte of value 1.
    * 
    * struct {
    *    enum { change_cipher_spec(1), (255) } type;
    * } ChangeCipherSpec;
    * 
    * @return the ChangeCipherSpec byte buffer.
    */
   tls.createChangeCipherSpec = function()
   {
      var rval = forge.util.createBuffer();
      rval.putByte(0x01);
      return rval;
   };
   
   /**
    * Creates a Finished message.
    * 
    * struct {
    *    opaque verify_data[12];
    * } Finished;
    *
    * verify_data
    *    PRF(master_secret, finished_label, MD5(handshake_messages) +
    *    SHA-1(handshake_messages)) [0..11];
    *
    * finished_label
    *    For Finished messages sent by the client, the string "client
    *    finished". For Finished messages sent by the server, the
    *    string "server finished".
    *
    * handshake_messages
    *    All of the data from all handshake messages up to but not
    *    including this message. This is only data visible at the
    *    handshake layer and does not include record layer headers.
    *    This is the concatenation of all the Handshake structures as
    *    defined in 7.4 exchanged thus far.
    * 
    * @param c the connection.
    * 
    * @return the Finished byte buffer.
    */
   tls.createFinished = function(c)
   {
      // generate verify_data
      var b = forge.util.createBuffer();
      b.putBuffer(c.handshakeState.md5.digest());
      b.putBuffer(c.handshakeState.sha1.digest());
      
      // TODO: determine prf function and verify length for TLS 1.2
      var sp = c.handshakeState.sp;
      var vdl = 12;
      var prf = prf_TLS1;
      b = prf(sp.master_secret, 'client finished', b.getBytes(), vdl);
      
      // build record fragment
      var rval = forge.util.createBuffer();
      rval.putByte(tls.HandshakeType.finished);
      rval.putInt24(b.length());
      rval.putBuffer(b);
      return rval;
   };
   
   /**
    * Fragments, compresses, encrypts, and queues a record for delivery.
    * 
    * @param c the connection.
    * @param record the record to queue.
    */
   tls.queue = function(c, record)
   {
      // if the record is a handshake record, update handshake hashes
      if(record.type === tls.ContentType.handshake)
      {
         var bytes = record.fragment.bytes();
         c.handshakeState.md5.update(bytes);
         c.handshakeState.sha1.update(bytes);
         bytes = null;
      }
      
      // handle record fragmentation
      var records;
      if(record.fragment.length() <= tls.MaxFragment)
      {
         records = [record];
      }
      else
      {
         // fragment data as long as it is too long
         records = [];
         var data = record.fragment.bytes();
         while(data.length > tls.MaxFragment)
         {
            records.push(tls.createRecord(
            {
               type: record.type,
               data: forge.util.createBuffer(data.splice(0, tls.MaxFragment))
            }));
         }
         // add last record
         if(data.length > 0)
         {
            records.push(tls.createRecord(
            {
               type: record.type,
               data: forge.util.createBuffer(data)
            }));
         }
      }
      
      // compress and encrypt all fragmented records
      for(var i = 0; i < records.length && !c.fail; ++i)
      {
         // update the record using current write state
         var rec = records[i];
         var s = c.state.current.write;
         if(s.update(c, rec))
         {
            // store record
            c.records.push(rec);
         }
      }
   };
   
   /**
    * Flushes all queued records to the output buffer and calls the
    * tlsDataReady() handler on the given connection.
    * 
    * @param c the connection.
    * 
    * @return true on success, false on failure.
    */
   tls.flush = function(c)
   {
      for(var i = 0; i < c.records.length; ++i)
      {
         var record = c.records[i];
         
         // add record header and fragment
         c.tlsData.putByte(record.type);
         c.tlsData.putByte(record.version.major);
         c.tlsData.putByte(record.version.minor);
         c.tlsData.putInt16(record.fragment.length());
         c.tlsData.putBuffer(c.records[i].fragment);
      }
      c.records = [];
      return c.tlsDataReady(c);
   };
   
   /**
    * Verifies a certificate chain against the given connection's
    * Certificate Authority store.
    * 
    * @param c the TLS connection.
    * @param chain the certificate chain to verify, with the root or highest
    *           authority at the end.
    * 
    * @return true if successful, false if not.
    */
   tls.verifyCertificateChain = function(c, chain)
   {
      /* From: RFC3280 - Internet X.509 Public Key Infrastructure Certificate
         Section 6: Certification Path Validation
         See inline parentheticals related to this particular implementation.
         
         The primary goal of path validation is to verify the binding between
         a subject distinguished name or a subject alternative name and
         subject public key, as represented in the end entity certificate,
         based on the public key of the trust anchor. This requires obtaining
         a sequence of certificates that support that binding. That sequence
         should be provided in the passed 'chain'. The trust anchor should be
         in the connection's CA store. The 'end entity' certificate is the
         certificate provided by the server.
         
         To meet this goal, the path validation process verifies, among other
         things, that a prospective certification path (a sequence of n
         certificates or a 'chain') satisfies the following conditions:
         
         (a) for all x in {1, ..., n-1}, the subject of certificate x is
         the issuer of certificate x+1;
         
         (b) certificate 1 is issued by the trust anchor;
         
         (c) certificate n is the certificate to be validated; and
         
         (d) for all x in {1, ..., n}, the certificate was valid at the
             time in question.
         
         Note that here 'n' is index 0 in the chain and 1 is the last
         certificate in the chain and it must be signed by a certificate
         in the connection's CA store.
         
         The path validation process also determines the set of certificate
         policies that are valid for this path, based on the certificate
         policies extension, policy mapping extension, policy constraints
         extension, and inhibit any-policy extension.
         
         Note: Policy mapping extension not supported (Not Required).
         
         Note: If the certificate has an unsupported critical extension, then
         it must be rejected.
         
         Note: A certificate is self-issued if the DNs that appear in the
         subject and issuer fields are identical and are not empty.
         
         The path validation algorithm assumes the following seven inputs
         are provided to the path processing logic. What this specific
         implementation will use is provided parenthetically:
         
         (a) a prospective certification path of length n (the 'chain')
         (b) the current date/time: ('now').
         (c) user-initial-policy-set: A set of certificate policy identifiers
                naming the policies that are acceptable to the certificate
                user. The user-initial-policy-set contains the special value
                any-policy if the user is not concerned about certificate
                policy (Not implemented. Any policy is accepted).
         (d) trust anchor information, describing a CA that serves as a
                trust anchor for the certification path. The trust anchor
                information includes:
            
            (1)  the trusted issuer name,
            (2)  the trusted public key algorithm,
            (3)  the trusted public key, and
            (4)  optionally, the trusted public key parameters associated
                 with the public key.
             
            (Trust anchors are provided via certificates in the CA store).
            
            The trust anchor information may be provided to the path
            processing procedure in the form of a self-signed certificate.
            The trusted anchor information is trusted because it was delivered
            to the path processing procedure by some trustworthy out-of-band
            procedure. If the trusted public key algorithm requires
            parameters, then the parameters are provided along with the
            trusted public key (No parameters used in this implementation).
         
         (e) initial-policy-mapping-inhibit, which indicates if policy
                mapping is allowed in the certification path.
                (Not implemented, no policy checking)
         
         (f) initial-explicit-policy, which indicates if the path must be
                valid for at least one of the certificate policies in the user-
                initial-policy-set.
                (Not implemented, no policy checking)
         
         (g) initial-any-policy-inhibit, which indicates whether the
                anyPolicy OID should be processed if it is included in a
                certificate.
                (Not implemented, so any policy is valid provided that it is
                 not marked as critical)
       */
      
      /* Basic Path Processing:
       
         For each certificate in the 'chain', the following is checked:
         
         1. The certificate validity period includes the current time.
         2. The certificate was signed by its parent (where the parent is
            either the next in the chain or from the CA store).
         3. TODO: The certificate has not been revoked.
         4. The certificate issuer name matches the parent's subject name.
         5. TODO: If the certificate is self-issued and not the final
            certificate in the chain, skip this step, otherwise verify
            that the subject name is within one of the permitted subtrees
            of X.500 distinguished names and that each of the alternative
            names in the subjectAltName extension (critical or non-critical)
            is within one of the permitted subtrees for that name type.
         6. TODO: If the certificate is self-issued and not the final
            certificate in the chain, skip this step, otherwise verify that
            the subject name is not within one of the excluded subtrees for
            X.500 distinguished names and none of the subjectAltName extension
            names are excluded for that name type.
         7. The other steps in the algorithm for basic path processing involve
            handling the policy extension which is not presently supported
            in this implementation. Instead, if a critical policy extension
            is found, the certificate is rejected as not supported.
         8. If the certificate is not the first or the only certificate in
            the chain and it has a critical key usage extension, verify that
            the keyCertSign bit is set. If the key usage extension exists,
            verify that the basic constraints extension exists. If the basic
            constraints extension exists, verify that the cA flag is set.
            TODO: handle pathLenConstraint by setting max path length to a
            lower number if the parent certificate's pathLenConstraint is lower.
            Also ensure that the path isn't already too long.
       */
      
      // copy cert chain references to another array and get CA store
      chain = chain.slice(0);
      var certs = chain.slice(0);
      var caStore = c.caStore;
      
      // get current date
      var now = new Date();
      
      // verify each cert in the chain using its parent, where the parent
      // is either the next in the chain or from the CA store
      var first = true;
      var error = null;
      var depth = 0;
      var cert, parent;
      do
      {
         cert = chain.shift();
         
         // 1. check valid time
         if(now < cert.validity.notBefore || now > cert.validity.notAfter)
         {
            error = {
               message: 'Certificate not valid yet or has expired.',
               send: true,
               origin: 'client',
               alert: {
                  level: tls.Alert.Level.fatal,
                  description: tls.Alert.Description.certificate_expired
               },
               notBefore: cert.validity.notBefore,
               notAfter: cert.validity.notAfter,
               now: now
            };
         }
         // 2. verify with parent
         else
         {
            // get parent from chain
            var verified = false;
            if(chain.length > 0)
            {
               // verify using parent
               parent = chain[0];
               try
               {
                  verified = parent.verify(cert);
               }
               catch(ex)
               {
                  // failure to verify, don't care why, just fail
               }
            }
            // get parent from CA store
            else
            {
               // CA store might have multiple certificates where the issuer
               // can't be determined from the certificate (unlikely case for
               // old certificates) so normalize by always putting parents into
               // an array
               var parents = caStore.getIssuer(cert);
               if(parents === null)
               {
                  // no parent issuer, so certificate not trusted
                  error = {
                     message: 'Untrusted certificate.',
                     send: true,
                     origin: 'client',
                     alert: {
                        level: tls.Alert.Level.fatal,
                        description: tls.Alert.Description.unknown_ca
                     }
                  };
               }
               else
               {
                  if(parents.constructor != Array)
                  {
                     parents = [parents];
                  }
                  
                  // multiple parents to try verifying with
                  while(!verified && parents.length > 0)
                  {
                     parent = parents.shift();
                     try
                     {
                        verified = parent.verify(cert);
                     }
                     catch(ex)
                     {
                        // failure to verify, try next one
                     }
                  }
               }
            }
            if(error === null && !verified)
            {
               error = {
                  message: 'Certificate signature invalid.',
                  send: true,
                  origin: 'client',
                  alert: {
                     level: tls.Alert.Level.fatal,
                     description: tls.Alert.Description.bad_certificate
                  }
               };
            }
         }
         
         // TODO: 3. check revoked
         
         // 4. check for matching issuer/subject
         if(error === null && !parent.isIssuer(cert))
         {
            // parent is not issuer
            error = {
               message: 'Certificate issuer invalid.',
               send: true,
               origin: 'client',
               alert: {
                  level: tls.Alert.Level.fatal,
                  description: tls.Alert.Description.bad_certificate
               }
            };
         }
         
         // 5. TODO: check names with permitted names tree
         
         // 6. TODO: check names against excluded names tree
         
         // 7. check for unsupported critical extensions
         if(error === null)
         {
            // supported extensions
            var se = {
               keyUsage: true,
               basicConstraints: true
            };
            for(var i = 0; error === null && i < cert.extensions.length; ++i)
            {
               var ext = cert.extensions[i];
               if(ext.critical && !(ext.name in se))
               {
                  error = {
                     message: 'Certificate has unsupported critical extension.',
                     send: true,
                     origin: 'client',
                     alert: {
                        level: tls.Alert.Level.fatal,
                        description:
                           tls.Alert.Description.unsupported_certificate
                     }
                  };
               }
            }
         }
         
         // 8. check for CA if not first or only certificate, first for
         // keyUsage extension and then for basic constraints
         if(!first || chain.length === 0)
         {
            var bcExt = cert.getExtension('basicConstraints');
            var keyUsageExt = cert.getExtension('keyUsage');
            if(keyUsageExt !== null)
            {
               // keyCertSign must be true and there must be a basic
               // constraints extension
               if(!keyUsageExt.keyCertSign || bcExt === null)
               {
                  // bad certificate
                  error = {
                     message:
                        'Certificate keyUsage or basicConstraints ' +
                        'conflict or indicate certificate is not a CA.',
                     send: true,
                     origin: 'client',
                     alert: {
                        level: tls.Alert.Level.fatal,
                        description:
                           tls.Alert.Description.bad_certificate
                     }
                  };
               }
            }
            // basic constraints cA flag must be set
            if(error === null && bcExt !== null)
            {
               // bad certificate
               error = {
                  message:
                     'Certificate basicConstraints indicates certificate ' +
                     'is not a CA.',
                  send: true,
                  origin: 'client',
                  alert: {
                     level: tls.Alert.Level.fatal,
                     description:
                        tls.Alert.Description.bad_certificate
                  }
               };
            }
         }
         
         // call application callback
         var vfd = (error === null) ? true : error.alert.description;
         var ret = c.verify(c, vfd, depth, certs);
         if(ret === true)
         {
            // clear any set error
            error = null;
         }
         else
         {
            // if passed basic tests, set default message and alert
            if(vfd === true)
            {
               error = {
                  message: 'Application rejected certificate.',
                  send: true,
                  origin: 'client',
                  alert: {
                     level: tls.Alert.Level.fatal,
                     description: tls.Alert.Description.bad_certificate
                  }
               };
            }
            
            // check for custom alert info
            if(ret || ret === 0)
            {
               // set custom message and alert description
               if(ret.constructor == Object)
               {
                  if(ret.message)
                  {
                     error.message = ret.message;
                  }
                  if(ret.alert)
                  {
                     error.alert.description = ret.alert;
                  }
               }
               else if(ret.constructor == Number)
               {
                  // set custom alert description
                  error.alert.description = ret;
               }
            }
            
            // send error
            c.error(c, error);
         }
         
         // no longer first cert in chain
         first = false;
         ++depth;
      }
      while(!c.fail && chain.length > 0);
      
      return !c.fail;
   };
   
   /**
    * Creates a new TLS connection.
    * 
    * See public createConnection() docs for more details.
    * 
    * @param options the options for this connection.
    * 
    * @return the new TLS connection.
    */
   tls.createConnection = function(options)
   {
      var caStore = null;
      if(options.caStore)
      {
         // if CA store is an array, convert it to a CA store object
         if(options.caStore.constructor == Array)
         {
            caStore = forge.pki.createCaStore(options.caStore);
         }
         else
         {
            caStore = options.caStore;
         }
      }
      else
      {
         // create empty CA store
         caStore = forge.pki.createCaStore();
      }
      
      // setup default cipher suites
      var cipherSuites = options.cipherSuites || null;
      if(cipherSuites === null)
      {
         cipherSuites = [];
         cipherSuites.push(tls.CipherSuites.TLS_RSA_WITH_AES_128_CBC_SHA);
         cipherSuites.push(tls.CipherSuites.TLS_RSA_WITH_AES_256_CBC_SHA);
      }
      
      // create TLS connection
      var c =
      {
         sessionId: options.sessionId,
         caStore: caStore,
         sessionCache: options.sessionCache,
         cipherSuites: cipherSuites,
         connected: options.connected,
         virtualHost: options.virtualHost || null,
         verify: options.verify || function(cn,vfd,dpth,cts){return vfd;},
         getCertificate: options.getCertificate || null,
         getPrivateKey: options.getPrivateKey || null,
         getSignature: options.getSignature || null,
         input: forge.util.createBuffer(),
         tlsData: forge.util.createBuffer(),
         data: forge.util.createBuffer(),
         tlsDataReady: options.tlsDataReady,
         dataReady: options.dataReady,
         closed: options.closed,
         error: function(c, ex)
         {
            // send TLS alert
            if(ex.send)
            {
               var record = tls.createAlert(ex.alert);
               tls.queue(c, record);
               tls.flush(c);
            }
            
            // error is fatal by default
            var fatal = (ex.fatal !== false);
            if(fatal)
            {
               // set fail flag
               c.fail = true;
            }
            
            // call error handler first
            options.error(c, ex);
            
            if(fatal)
            {
               // fatal error, close connection
               c.close();
            }
         },
         deflate: options.deflate || null,
         inflate: options.inflate || null
      };
      
      /**
       * Resets a closed TLS connection for reuse. Called in c.close().
       */
      c.reset = function()
      {
         c.record = null;
         c.sessionId = null;
         c.session = null;
         c.state =
         {
            pending: null,
            current: null
         };
         c.expect = SHE;
         c.fragmented = null;
         c.records = [];
         c.open = false;
         c.firstHandshake = false;
         c.handshakeState = null;
         c.isConnected = false;
         c.fail = false;
         c.input.clear();
         c.tlsData.clear();
         c.data.clear();
         c.state.current = tls.createConnectionState(c);
      };
      
      // do initial reset of connection
      c.reset();
      
      /**
       * Updates the current TLS engine state based on the given record.
       * 
       * @param c the TLS connection.
       * @param record the TLS record to act on.
       */
      var _update = function(c, record)
      {
         // get record handler (align type in table by subtracting lowest)
         var aligned = record.type - tls.ContentType.change_cipher_spec;
         var handlers = ctTable[c.expect];
         if(aligned in handlers)
         {
            handlers[aligned](c, record);
         }
         else
         {
            // unexpected record
            tls.handleUnexpected(c, record);
         }
      };
      
      /**
       * Performs a handshake using the TLS Handshake Protocol.
       * 
       * @param sessionId the session ID to use, null to start a new one.
       */
      c.handshake = function(sessionId)
      {
         // if a handshake is already in progress, fail
         if(c.handshakeState)
         {
            // not fatal error
            c.error(c, {
               message: 'Handshake already in progress.',
               fatal: false
            });
         }
         else
         {
            // default to blank (new session)
            sessionId = sessionId || '';
            
            // if a session ID was specified, find it in the cache
            var session = null;
            if(sessionId.length > 0)
            {
               var key = forge.util.bytesToHex(sessionId);
               if(c.sessionCache && key in c.sessionCache)
               {
                  // get cached session and remove from cache
                  session = c.sessionCache[key];
                  delete c.sessionCache[key];
               }
               else
               {
                  // session ID not cached, clear it
                  sessionId = '';
               }
            }
            // else grab a session from the cache, if available
            if(sessionId.length === 0 && c.sessionCache)
            {
               for(var key in c.sessionCache)
               {
                  session = c.sessionCache[key];
                  sessionId = session.id;
                  delete c.sessionCache[key];
                  break;
               }
            }
            
            // create random
            var random = tls.createRandom();
            
            // create client hello
            var record = tls.createRecord(
            {
               type: tls.ContentType.handshake,
               data: tls.createClientHello(c, sessionId, random)
            });
            
            // TODO: clean up session/handshake state design
            
            // create new handshake state
            c.handshakeState =
            {
               sessionId: sessionId,
               session: session,
               serverCertificate: null,
               certificateRequest: null,
               certificate: null,
               sp: null,
               clientRandom: random.bytes(),
               md5: forge.md.md5.create(),
               sha1: forge.md.sha1.create()
            };
            
            // connection now open
            c.open = true;
            
            // send hello
            tls.queue(c, record);
            tls.flush(c);
         }
      };
      
      /**
       * Called when TLS protocol data has been received from somewhere
       * and should be processed by the TLS engine.
       * 
       * @param data the TLS protocol data, as a string, to process.
       * 
       * @return 0 if the data could be processed, otherwise the
       *         number of bytes required for data to be processed.
       */
      c.process = function(data)
      {
         var rval = 0;
         
         // buffer data, get input length
         var b = c.input;
         if(data)
         {
            b.putBytes(data);
         }
         var len = b.length();
         
         // TODO: this function and c.record/c.fragment usage in general have
         // become messy due to redesigns (including going from procedural
         // loop to handle records to asynchronous functional record
         // processing), needs clean up and simplification
         
         // process next record if no failure, process will be called after
         // each record is handled (since handling can be asynchronous)
         if(!c.fail)
         {
            // reset record if ready and now empty
            if(c.record !== null &&
               c.record.ready && c.record.fragment.isEmpty())
            {
               c.record = null;
            }
            
            // if there is no pending record
            if(c.record === null)
            {
               if(len < 5)
               {
                  // need at least 5 bytes to initialize a record
                  rval = 5 - len;
               }
               else
               {
                  // do basic record initialization
                  c.record =
                  {
                     type: b.getByte(),
                     version:
                     {
                        major: b.getByte(),
                        minor: b.getByte()
                     },
                     length: b.getInt16(),
                     fragment: forge.util.createBuffer(),
                     ready: false
                  };
                  len -= 5;
                  
                  // check record version
                  if(c.record.version.major != tls.Version.major ||
                     c.record.version.minor != tls.Version.minor)
                  {
                     c.error(c, {
                        message: 'Incompatible TLS version.',
                        send: true,
                        origin: 'client',
                        alert: {
                           level: tls.Alert.Level.fatal,
                           description: tls.Alert.Description.protocol_version
                        }
                     });
                  }
               }
            }
            
            // handle pending record (record not yet ready)
            if(!c.fail && c.record !== null && !c.record.ready)
            {
               if(len < c.record.length)
               {
                  // not enough data yet, need remainder of record
                  rval = c.record.length - len;
               }
               // there is enough data to parse the pending record
               else
               {
                  // fill record fragment
                  c.record.fragment.putBytes(b.getBytes(c.record.length));
                  
                  // update record using current read state
                  var s = c.state.current.read;
                  if(s.update(c, c.record))
                  {
                     // if the record type matches a previously fragmented
                     // record, append the record fragment to it
                     if(c.fragmented !== null)
                     {
                        if(c.fragmented.type === c.record.type)
                        {
                           // concatenate record fragments
                           c.fragmented.fragment.putBuffer(c.record.fragment);
                           c.record = c.fragmented;
                        }
                        else
                        {
                           // error, invalid fragmented record
                           c.error(c, {
                              message: 'Invalid fragmented record.',
                              send: true,
                              origin: 'client',
                              alert: {
                                 level: tls.Alert.Level.fatal,
                                 description:
                                    tls.Alert.Description.unexpected_message
                              }
                           });
                        }
                     }
                     
                     // record is now ready
                     c.record.ready = true;
                  }
               }
            }
            
            // record ready to be handled
            if(!c.fail && c.record !== null && c.record.ready)
            {
               // update engine state
               _update(c, c.record);
            }
         }
         
         return rval;
      };
      
      /**
       * Requests that application data be packaged into a TLS record.
       * The tlsDataReady handler will be called when the TLS record(s) have
       * been prepared.
       * 
       * @param data the application data, as a string, to be sent.
       * 
       * @return true on success, false on failure.
       */
      c.prepare = function(data)
      {
         var record = tls.createRecord(
         {
            type: tls.ContentType.application_data,
            data: forge.util.createBuffer(data)
         });
         tls.queue(c, record);
         return tls.flush(c);
      };
      
      /**
       * Closes the connection (sends a close_notify alert).
       */
      c.close = function()
      {
         // save session if connection didn't fail
         if(!c.fail && c.sessionCache && c.session)
         {
            var key = forge.util.bytesToHex(c.sessionId);
            c.sessionCache[key] = c.session;
         }
         
         if(c.open)
         {
            // connection no longer open, clear input
            c.open = false;
            c.input.clear();
            if(c.isConnected)
            {
               // send close_notify alert
               var record = tls.createAlert(
               {
                  level: tls.Alert.Level.warning,
                  description: tls.Alert.Description.close_notify
               });
               tls.queue(c, record);
               tls.flush(c);
               
               // no longer connected
               c.isConnected = false;
               
               // call handler
               c.closed(c);
            }
         }
         
         // reset TLS connection
         c.reset();
      };
      
      return c;
   };
   
   /**
    * The crypto namespace and tls API.
    */
   forge.tls = {};
   
   // expose prf_tls1 for testing
   forge.tls.prf_tls1 = prf_TLS1;
   
   // expose TLS alerts
   forge.tls.Alert = tls.Alert;
   
   // expose cipher suites
   forge.tls.CipherSuites = tls.CipherSuites;
   
   /**
    * Creates a new TLS connection. This does not make any assumptions about
    * the transport layer that TLS is working on top of, ie: it does not
    * assume there is a TCP/IP connection or establish one. A TLS connection
    * is totally abstracted away from the layer is runs on top of, it merely
    * establishes a secure channel between a client" and a "server".
    * 
    * A TLS connection contains 4 connection states: pending read and write,
    * and current read and write.
    * 
    * At initialization, the current read and write states will be null.
    * Only once the security parameters have been set and the keys have
    * been generated can the pending states be converted into current
    * states. Current states will be updated for each record processed.
    * 
    * A custom certificate verify callback may be provided to check information
    * like the common name on the server's certificate. It will be called for
    * every certificate in the chain. It has the following signature:
    * 
    * variable func(c, certs, index, preVerify)
    * Where:
    * c         The TLS connection
    * verified  Set to true if certificate was verified, otherwise the alert
    *           tls.Alert.Description for why the certificate failed.
    * depth     The current index in the chain, where 0 is the server's cert.
    * certs     The certificate chain, *NOTE* if the server was anonymous
    *           then the chain will be empty.
    * 
    * The function returns true on success and on failure either the
    * appropriate tls.Alert.Description or an object with 'alert' set to
    * the appropriate tls.Alert.Description and 'message' set to a custom
    * error message. If true is not returned then the connection will abort
    * using, in order of availability, first the returned alert description,
    * second the preVerify alert description, and lastly the default
    * 'bad_certificate'.
    * 
    * There are three callbacks that can be used to make use of client-side
    * certificates where each takes the TLS connection as the first parameter:
    * 
    * getCertificate(conn, CertificateRequest)
    *    The second parameter is the CertificateRequest message from the server
    *    that is part of the TLS protocol. It can be examined to determine
    *    what client-side certificate to use (advanced). Most implementations
    *    will just return a client-side certificate. The return value must be
    *    a PEM-formatted certificate.
    * getPrivateKey(conn, certificate)
    *    The second parameter is an forge.pki X.509 certificate object that
    *    is associated with the requested private key. The return value must
    *    be a PEM-formatted private key.
    * getSignature(conn, bytes, callback)
    *    This callback can be used instead of getPrivateKey if the private key
    *    is not directly accessible in javascript or should not be. For
    *    instance, a secure external web service could provide the signature
    *    in exchange for appropriate credentials. The second parameter is a
    *    string of bytes to be signed that are part of the TLS protocol. These
    *    bytes are used to verify that the private key for the previously
    *    provided client-side certificate is accessible to the client. The
    *    callback is a function that takes 2 parameters, the TLS connection
    *    and the RSA encrypted (signed) bytes as a string. This callback must
    *    be called once the signature is ready.
    * 
    * @param options the options for this connection:
    *    sessionId: a session ID to reuse, null for a new connection.
    *    caStore: an array of certificates to trust.
    *    sessionCache: a session cache to use.
    *    cipherSuites: an optional array of cipher suites to use,
    *       see tls.CipherSuites.
    *    connected: function(conn) called when the first handshake completes.
    *    virtualHost: the virtual server name to use in a TLS SNI extension.
    *    verify: a handler used to custom verify certificates in the chain.
    *    getCertificate: an optional callback used to get a client-side
    *       certificate.
    *    getPrivateKey: an optional callback used to get a client-side
    *       private key.
    *    getSignature: an optional callback used to get a client-side
    *       signature.
    *    tlsDataReady: function(conn) called when TLS protocol data has
    *       been prepared and is ready to be used (typically sent over a
    *       socket connection to its destination), read from conn.tlsData
    *       buffer.
    *    dataReady: function(conn) called when application data has
    *       been parsed from a TLS record and should be consumed by the
    *       application, read from conn.data buffer.
    *    closed: function(conn) called when the connection has been closed.
    *    error: function(conn, error) called when there was an error.
    *    deflate: function(inBytes) if provided, will deflate TLS records using
    *       the deflate algorithm if the server supports it.
    *    inflate: function(inBytes) if provided, will inflate TLS records using
    *       the deflate algorithm if the server supports it.
    * 
    * @return the new TLS connection.
    */
   forge.tls.createConnection = function(options)
   {
      return tls.createConnection(options);
   };
   
   /**
    * Wraps a forge.net socket with a TLS layer.
    * 
    * @param options:
    *    sessionId: a session ID to reuse, null for a new connection if no
    *       session cache is provided or it is empty.
    *    caStore: an array of certificates to trust.
    *    sessionCache: a session cache to use.
    *    cipherSuites: an optional array of cipher suites to use,
    *       see tls.CipherSuites.
    *    socket: the socket to wrap.
    *    virtualHost: the virtual server name to use in a TLS SNI extension.
    *    verify: a handler used to custom verify certificates in the chain.
    *    getCertificate: an optional callback used to get a client-side
    *       certificate.
    *    getPrivateKey: an optional callback used to get a client-side
    *       private key.
    *    getSignature: an optional callback used to get a client-side
    *       signature.
    *    deflate: function(inBytes) if provided, will deflate TLS records using
    *       the deflate algorithm if the server supports it.
    *    inflate: function(inBytes) if provided, will inflate TLS records using
    *       the deflate algorithm if the server supports it.
    * 
    * @return the TLS-wrapped socket.
    */
   forge.tls.wrapSocket = function(options)
   {
      // get raw socket
      var socket = options.socket;
      
      // create TLS socket
      var tlsSocket =
      {
         id: socket.id,
         // set handlers
         connected: socket.connected || function(e){},
         closed: socket.closed || function(e){},
         data: socket.data || function(e){},
         error: socket.error || function(e){}
      };
      
      // create TLS connection
      var c = forge.tls.createConnection({
         sessionId: options.sessionId || null,
         caStore: options.caStore || [],
         sessionCache: options.sessionCache || null,
         cipherSuites: options.cipherSuites || null,
         virtualHost: options.virtualHost,
         verify: options.verify,
         getCertificate: options.getCertificate,
         getPrivateKey: options.getPrivateKey,
         getSignature: options.getSignature,
         deflate: options.deflate,
         inflate: options.inflate,
         connected: function(c)
         {
            // update session ID
            c.sessionId = c.handshakeState.sessionId;
            
            // save session if caching
            if(c.sessionCache)
            {
               c.session =
               {
                  id: c.sessionId,
                  sp: c.handshakeState.sp
               };
               c.session.sp.keys = null;
            }
            
            // clean up handshake state
            c.handshakeState = null;
            
            // first handshake complete, call handler
            if(!c.firstHandshake)
            {
               c.firstHandshake = true;
               tlsSocket.connected({
                  id: socket.id,
                  type: 'connect',
                  bytesAvailable: c.data.length()
               });
            }
         },
         tlsDataReady: function(c)
         {
            // send TLS data over socket
            return socket.send(c.tlsData.getBytes());
         },
         dataReady: function(c)
         {
            // indicate application data is ready
            tlsSocket.data({
               id: socket.id,
               type: 'socketData',
               bytesAvailable: c.data.length()
            });
         },
         closed: function(c)
         {
            // close socket
            socket.close();
         },
         error: function(c, e)
         {
            // close socket, send error
            socket.close();
            tlsSocket.error({
               id: socket.id,
               type: 'tlsError',
               message: e.message,
               bytesAvailable: 0,
               error: e
            });
         }
      });
      
      // handle doing handshake after connecting
      socket.connected = function(e)
      {
         c.handshake(options.sessionId);
      };
      
      // handle closing TLS connection
      socket.closed = function(e)
      {
         if(c.open && c.handshakeState)
         {
            // error
            tlsSocket.error({
               id: socket.id,
               type: 'ioError',
               message: 'Connection closed during handshake.',
               bytesAvailable: 0
            });
         }
         c.isConnected = false;
         c.close();
         
         // call socket handler
         tlsSocket.closed({
            id: socket.id,
            type: 'close',
            bytesAvailable: 0
         });
      };
      
      // handle error on socket
      socket.error = function(e)
      {
         // error
         tlsSocket.error({
            id: socket.id,
            type: e.type,
            message: e.message,
            bytesAvailable: 0
         });
         c.close();
      };
      
      // handle receiving raw TLS data from socket
      var _requiredBytes = 0;
      socket.data = function(e)
      {
         // drop data if connection not open
         if(!c.open)
         {
            socket.receive(e.bytesAvailable);
         }
         else
         {
            // only receive if there are enough bytes available to
            // process a record
            if(e.bytesAvailable >= _requiredBytes)
            {
               var count = Math.max(e.bytesAvailable, _requiredBytes);
               var data = socket.receive(count);
               if(data !== null)
               {
                  _requiredBytes = c.process(data);
               }
            }
         }
      };
      
      /**
       * Destroys this socket.
       */
      tlsSocket.destroy = function()
      {
         socket.destroy();
      };
      
      /**
       * Sets this socket's TLS session cache. This should be called before
       * the socket is connected or after it is closed.
       * 
       * The cache is an object mapping session IDs to internal opaque state.
       * An application might need to change the cache used by a particular
       * tlsSocket between connections if it accesses multiple TLS hosts.
       * 
       * @param cache the session cache to use.
       */
      tlsSocket.setSessionCache = function(cache)
      {
         c.sessionCache = cache;
      };
      
      /**
       * Connects this socket.
       * 
       * @param options:
       *           host: the host to connect to.
       *           port: the port to connect to.
       *           policyPort: the policy port to use (if non-default), 0 to
       *              use the flash default.
       *           policyUrl: the policy file URL to use (instead of port). 
       */
      tlsSocket.connect = function(options)
      {
         socket.connect(options);
      };
      
      /**
       * Closes this socket.
       */
      tlsSocket.close = function()
      {
         c.close();
      };
      
      /**
       * Determines if the socket is connected or not.
       * 
       * @return true if connected, false if not.
       */
      tlsSocket.isConnected = function()
      {
         return c.isConnected && socket.isConnected();
      };
      
      /**
       * Writes bytes to this socket.
       * 
       * @param bytes the bytes (as a string) to write.
       * 
       * @return true on success, false on failure.
       */
      tlsSocket.send = function(bytes)
      {
         return c.prepare(bytes);
      };
      
      /**
       * Reads bytes from this socket (non-blocking). Fewer than the number
       * of bytes requested may be read if enough bytes are not available.
       * 
       * This method should be called from the data handler if there are
       * enough bytes available. To see how many bytes are available, check
       * the 'bytesAvailable' property on the event in the data handler or
       * call the bytesAvailable() function on the socket. If the browser is
       * msie, then the bytesAvailable() function should be used to avoid
       * race conditions. Otherwise, using the property on the data handler's
       * event may be quicker.
       * 
       * @param count the maximum number of bytes to read.
       * 
       * @return the bytes read (as a string) or null on error.
       */
      tlsSocket.receive = function(count)
      {
         return c.data.getBytes(count);
      };
      
      /**
       * Gets the number of bytes available for receiving on the socket.
       * 
       * @return the number of bytes available for receiving.
       */
      tlsSocket.bytesAvailable = function()
      {
         return c.data.length();
      };
      
      return tlsSocket;
   };
})();
