/**
 * Advanced Encryption Standard (AES) Cipher-Block Chaining implementation.
 *
 * This implementation is based on the public domain library 'jscrypto' which
 * was written by:
 *
 * Emily Stark (estark@stanford.edu)
 * Mike Hamburg (mhamburg@stanford.edu)
 * Dan Boneh (dabo@cs.stanford.edu)
 *
 * Parts of this code are based on the OpenSSL implementation of AES:
 * http://www.openssl.org
 *
 * @author Dave Longley
 *
 * Copyright (c) 2010-2013 Digital Bazaar, Inc.
 */
(function() {
/* ########## Begin module implementation ########## */
function initModule(forge) {

var init = false; // not yet initialized
var Nb = 4;       // number of words comprising the state (AES = 4)
var sbox;         // non-linear substitution table used in key expansion
var isbox;        // inversion of sbox
var rcon;         // round constant word array
var mix;          // mix-columns table
var imix;         // inverse mix-columns table

/**
 * Performs initialization, ie: precomputes tables to optimize for speed.
 *
 * One way to understand how AES works is to imagine that 'addition' and
 * 'multiplication' are interfaces that require certain mathematical
 * properties to hold true (ie: they are associative) but they might have
 * different implementations and produce different kinds of results ...
 * provided that their mathematical properties remain true. AES defines
 * its own methods of addition and multiplication but keeps some important
 * properties the same, ie: associativity and distributivity. The
 * explanation below tries to shed some light on how AES defines addition
 * and multiplication of bytes and 32-bit words in order to perform its
 * encryption and decryption algorithms.
 *
 * The basics:
 *
 * The AES algorithm views bytes as binary representations of polynomials
 * that have either 1 or 0 as the coefficients. It defines the addition
 * or subtraction of two bytes as the XOR operation. It also defines the
 * multiplication of two bytes as a finite field referred to as GF(2^8)
 * (Note: 'GF' means "Galois Field" which is a field that contains a finite
 * number of elements so GF(2^8) has 256 elements).
 *
 * This means that any two bytes can be represented as binary polynomials;
 * when they multiplied together and modularly reduced by an irreducible
 * polynomial of the 8th degree, the results are the field GF(2^8). The
 * specific irreducible polynomial that AES uses in hexadecimal is 0x11b.
 * This multiplication is associative with 0x01 as the identity:
 *
 * (b * 0x01 = GF(b, 0x01) = b).
 *
 * The operation GF(b, 0x02) can be performed at the byte level by left
 * shifting b once and then XOR'ing it (to perform the modular reduction)
 * with 0x11b if b is >= 128. Repeated application of the multiplication
 * of 0x02 can be used to implement the multiplication of any two bytes.
 *
 * For instance, multiplying 0x57 and 0x13, denoted as GF(0x57, 0x13), can
 * be performed by factoring 0x13 into 0x01, 0x02, and 0x10. Then these
 * factors can each be multiplied by 0x57 and then added together. To do
 * the multiplication, values for 0x57 multiplied by each of these 3 factors
 * can be precomputed and stored in a table. To add them, the values from
 * the table are XOR'd together.
 *
 * AES also defines addition and multiplication of words, that is 4-byte
 * numbers represented as polynomials of 3 degrees where the coefficients
 * are the values of the bytes.
 *
 * The word [a0, a1, a2, a3] is a polynomial a3x^3 + a2x^2 + a1x + a0.
 *
 * Addition is performed by XOR'ing like powers of x. Multiplication
 * is performed in two steps, the first is an algebriac expansion as
 * you would do normally (where addition is XOR). But the result is
 * a polynomial larger than 3 degrees and thus it cannot fit in a word. So
 * next the result is modularly reduced by an AES-specific polynomial of
 * degree 4 which will always produce a polynomial of less than 4 degrees
 * such that it will fit in a word. In AES, this polynomial is x^4 + 1.
 *
 * The modular product of two polynomials 'a' and 'b' is thus:
 *
 * d(x) = d3x^3 + d2x^2 + d1x + d0
 * with
 * d0 = GF(a0, b0) ^ GF(a3, b1) ^ GF(a2, b2) ^ GF(a1, b3)
 * d1 = GF(a1, b0) ^ GF(a0, b1) ^ GF(a3, b2) ^ GF(a2, b3)
 * d2 = GF(a2, b0) ^ GF(a1, b1) ^ GF(a0, b2) ^ GF(a3, b3)
 * d3 = GF(a3, b0) ^ GF(a2, b1) ^ GF(a1, b2) ^ GF(a0, b3)
 *
 * As a matrix:
 *
 * [d0] = [a0 a3 a2 a1][b0]
 * [d1]   [a1 a0 a3 a2][b1]
 * [d2]   [a2 a1 a0 a3][b2]
 * [d3]   [a3 a2 a1 a0][b3]
 *
 * Special polynomials defined by AES (0x02 == {02}):
 * a(x)    = {03}x^3 + {01}x^2 + {01}x + {02}
 * a^-1(x) = {0b}x^3 + {0d}x^2 + {09}x + {0e}.
 *
 * These polynomials are used in the MixColumns() and InverseMixColumns()
 * operations, respectively, to cause each element in the state to affect
 * the output (referred to as diffusing).
 *
 * RotWord() uses: a0 = a1 = a2 = {00} and a3 = {01}, which is the
 * polynomial x3.
 *
 * The ShiftRows() method modifies the last 3 rows in the state (where
 * the state is 4 words with 4 bytes per word) by shifting bytes cyclically.
 * The 1st byte in the second row is moved to the end of the row. The 1st
 * and 2nd bytes in the third row are moved to the end of the row. The 1st,
 * 2nd, and 3rd bytes are moved in the fourth row.
 *
 * More details on how AES arithmetic works:
 *
 * In the polynomial representation of binary numbers, XOR performs addition
 * and subtraction and multiplication in GF(2^8) denoted as GF(a, b)
 * corresponds with the multiplication of polynomials modulo an irreducible
 * polynomial of degree 8. In other words, for AES, GF(a, b) will multiply
 * polynomial 'a' with polynomial 'b' and then do a modular reduction by
 * an AES-specific irreducible polynomial of degree 8.
 *
 * A polynomial is irreducible if its only divisors are one and itself. For
 * the AES algorithm, this irreducible polynomial is:
 *
 * m(x) = x^8 + x^4 + x^3 + x + 1,
 *
 * or {01}{1b} in hexadecimal notation, where each coefficient is a bit:
 * 100011011 = 283 = 0x11b.
 *
 * For example, GF(0x57, 0x83) = 0xc1 because
 *
 * 0x57 = 87  = 01010111 = x^6 + x^4 + x^2 + x + 1
 * 0x85 = 131 = 10000101 = x^7 + x + 1
 *
 * (x^6 + x^4 + x^2 + x + 1) * (x^7 + x + 1)
 * =  x^13 + x^11 + x^9 + x^8 + x^7 +
 *    x^7 + x^5 + x^3 + x^2 + x +
 *    x^6 + x^4 + x^2 + x + 1
 * =  x^13 + x^11 + x^9 + x^8 + x^6 + x^5 + x^4 + x^3 + 1 = y
 *    y modulo (x^8 + x^4 + x^3 + x + 1)
 * =  x^7 + x^6 + 1.
 *
 * The modular reduction by m(x) guarantees the result will be a binary
 * polynomial of less than degree 8, so that it can fit in a byte.
 *
 * The operation to multiply a binary polynomial b with x (the polynomial
 * x in binary representation is 00000010) is:
 *
 * b_7x^8 + b_6x^7 + b_5x^6 + b_4x^5 + b_3x^4 + b_2x^3 + b_1x^2 + b_0x^1
 *
 * To get GF(b, x) we must reduce that by m(x). If b_7 is 0 (that is the
 * most significant bit is 0 in b) then the result is already reduced. If
 * it is 1, then we can reduce it by subtracting m(x) via an XOR.
 *
 * It follows that multiplication by x (00000010 or 0x02) can be implemented
 * by performing a left shift followed by a conditional bitwise XOR with
 * 0x1b. This operation on bytes is denoted by xtime(). Multiplication by
 * higher powers of x can be implemented by repeated application of xtime().
 *
 * By adding intermediate results, multiplication by any constant can be
 * implemented. For instance:
 *
 * GF(0x57, 0x13) = 0xfe because:
 *
 * xtime(b) = (b & 128) ? (b << 1 ^ 0x11b) : (b << 1)
 *
 * Note: We XOR with 0x11b instead of 0x1b because in javascript our
 * datatype for b can be larger than 1 byte, so a left shift will not
 * automatically eliminate bits that overflow a byte ... by XOR'ing the
 * overflow bit with 1 (the extra one from 0x11b) we zero it out.
 *
 * GF(0x57, 0x02) = xtime(0x57) = 0xae
 * GF(0x57, 0x04) = xtime(0xae) = 0x47
 * GF(0x57, 0x08) = xtime(0x47) = 0x8e
 * GF(0x57, 0x10) = xtime(0x8e) = 0x07
 *
 * GF(0x57, 0x13) = GF(0x57, (0x01 ^ 0x02 ^ 0x10))
 *
 * And by the distributive property (since XOR is addition and GF() is
 * multiplication):
 *
 * = GF(0x57, 0x01) ^ GF(0x57, 0x02) ^ GF(0x57, 0x10)
 * = 0x57 ^ 0xae ^ 0x07
 * = 0xfe.
 */
var initialize = function() {
  init = true;

  /* Populate the Rcon table. These are the values given by
    [x^(i-1),{00},{00},{00}] where x^(i-1) are powers of x (and x = 0x02)
    in the field of GF(2^8), where i starts at 1.

    rcon[0] = [0x00, 0x00, 0x00, 0x00]
    rcon[1] = [0x01, 0x00, 0x00, 0x00] 2^(1-1) = 2^0 = 1
    rcon[2] = [0x02, 0x00, 0x00, 0x00] 2^(2-1) = 2^1 = 2
    ...
    rcon[9]  = [0x1B, 0x00, 0x00, 0x00] 2^(9-1)  = 2^8 = 0x1B
    rcon[10] = [0x36, 0x00, 0x00, 0x00] 2^(10-1) = 2^9 = 0x36

    We only store the first byte because it is the only one used.
  */
  rcon = [0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36];

  // compute xtime table which maps i onto GF(i, 0x02)
  var xtime = new Array(256);
  for(var i = 0; i < 128; ++i) {
    xtime[i] = i << 1;
    xtime[i + 128] = (i + 128) << 1 ^ 0x11B;
  }

  // compute all other tables
  sbox = new Array(256);
  isbox = new Array(256);
  mix = new Array(4);
  imix = new Array(4);
  for(var i = 0; i < 4; ++i) {
    mix[i] = new Array(256);
    imix[i] = new Array(256);
  }
  var e = 0, ei = 0, e2, e4, e8, sx, sx2, me, ime;
  for(var i = 0; i < 256; ++i) {
    /* We need to generate the SubBytes() sbox and isbox tables so that
      we can perform byte substitutions. This requires us to traverse
      all of the elements in GF, find their multiplicative inverses,
      and apply to each the following affine transformation:

      bi' = bi ^ b(i + 4) mod 8 ^ b(i + 5) mod 8 ^ b(i + 6) mod 8 ^
            b(i + 7) mod 8 ^ ci
      for 0 <= i < 8, where bi is the ith bit of the byte, and ci is the
      ith bit of a byte c with the value {63} or {01100011}.

      It is possible to traverse every possible value in a Galois field
      using what is referred to as a 'generator'. There are many
      generators (128 out of 256): 3,5,6,9,11,82 to name a few. To fully
      traverse GF we iterate 255 times, multiplying by our generator
      each time.

      On each iteration we can determine the multiplicative inverse for
      the current element.

      Suppose there is an element in GF 'e'. For a given generator 'g',
      e = g^x. The multiplicative inverse of e is g^(255 - x). It turns
      out that if use the inverse of a generator as another generator
      it will produce all of the corresponding multiplicative inverses
      at the same time. For this reason, we choose 5 as our inverse
      generator because it only requires 2 multiplies and 1 add and its
      inverse, 82, requires relatively few operations as well.

      In order to apply the affine transformation, the multiplicative
      inverse 'ei' of 'e' can be repeatedly XOR'd (4 times) with a
      bit-cycling of 'ei'. To do this 'ei' is first stored in 's' and
      'x'. Then 's' is left shifted and the high bit of 's' is made the
      low bit. The resulting value is stored in 's'. Then 'x' is XOR'd
      with 's' and stored in 'x'. On each subsequent iteration the same
      operation is performed. When 4 iterations are complete, 'x' is
      XOR'd with 'c' (0x63) and the transformed value is stored in 'x'.
      For example:

      s = 01000001
      x = 01000001

      iteration 1: s = 10000010, x ^= s
      iteration 2: s = 00000101, x ^= s
      iteration 3: s = 00001010, x ^= s
      iteration 4: s = 00010100, x ^= s
      x ^= 0x63

      This can be done with a loop where s = (s << 1) | (s >> 7). However,
      it can also be done by using a single 16-bit (in this case 32-bit)
      number 'sx'. Since XOR is an associative operation, we can set 'sx'
      to 'ei' and then XOR it with 'sx' left-shifted 1,2,3, and 4 times.
      The most significant bits will flow into the high 8 bit positions
      and be correctly XOR'd with one another. All that remains will be
      to cycle the high 8 bits by XOR'ing them all with the lower 8 bits
      afterwards.

      At the same time we're populating sbox and isbox we can precompute
      the multiplication we'll need to do to do MixColumns() later.
    */

    // apply affine transformation
    sx = ei ^ (ei << 1) ^ (ei << 2) ^ (ei << 3) ^ (ei << 4);
    sx = (sx >> 8) ^ (sx & 255) ^ 0x63;

    // update tables
    sbox[e] = sx;
    isbox[sx] = e;

    /* Mixing columns is done using matrix multiplication. The columns
      that are to be mixed are each a single word in the current state.
      The state has Nb columns (4 columns). Therefore each column is a
      4 byte word. So to mix the columns in a single column 'c' where
      its rows are r0, r1, r2, and r3, we use the following matrix
      multiplication:

      [2 3 1 1]*[r0,c]=[r'0,c]
      [1 2 3 1] [r1,c] [r'1,c]
      [1 1 2 3] [r2,c] [r'2,c]
      [3 1 1 2] [r3,c] [r'3,c]

      r0, r1, r2, and r3 are each 1 byte of one of the words in the
      state (a column). To do matrix multiplication for each mixed
      column c' we multiply the corresponding row from the left matrix
      with the corresponding column from the right matrix. In total, we
      get 4 equations:

      r0,c' = 2*r0,c + 3*r1,c + 1*r2,c + 1*r3,c
      r1,c' = 1*r0,c + 2*r1,c + 3*r2,c + 1*r3,c
      r2,c' = 1*r0,c + 1*r1,c + 2*r2,c + 3*r3,c
      r3,c' = 3*r0,c + 1*r1,c + 1*r2,c + 2*r3,c

      As usual, the multiplication is as previously defined and the
      addition is XOR. In order to optimize mixing columns we can store
      the multiplication results in tables. If you think of the whole
      column as a word (it might help to visualize by mentally rotating
      the equations above by counterclockwise 90 degrees) then you can
      see that it would be useful to map the multiplications performed on
      each byte (r0, r1, r2, r3) onto a word as well. For instance, we
      could map 2*r0,1*r0,1*r0,3*r0 onto a word by storing 2*r0 in the
      highest 8 bits and 3*r0 in the lowest 8 bits (with the other two
      respectively in the middle). This means that a table can be
      constructed that uses r0 as an index to the word. We can do the
      same with r1, r2, and r3, creating a total of 4 tables.

      To construct a full c', we can just look up each byte of c in
      their respective tables and XOR the results together.

      Also, to build each table we only have to calculate the word
      for 2,1,1,3 for every byte ... which we can do on each iteration
      of this loop since we will iterate over every byte. After we have
      calculated 2,1,1,3 we can get the results for the other tables
      by cycling the byte at the end to the beginning. For instance
      we can take the result of table 2,1,1,3 and produce table 3,2,1,1
      by moving the right most byte to the left most position just like
      how you can imagine the 3 moved out of 2,1,1,3 and to the front
      to produce 3,2,1,1.

      There is another optimization in that the same multiples of
      the current element we need in order to advance our generator
      to the next iteration can be reused in performing the 2,1,1,3
      calculation. We also calculate the inverse mix column tables,
      with e,9,d,b being the inverse of 2,1,1,3.

      When we're done, and we need to actually mix columns, the first
      byte of each state word should be put through mix[0] (2,1,1,3),
      the second through mix[1] (3,2,1,1) and so forth. Then they should
      be XOR'd together to produce the fully mixed column.
    */

    // calculate mix and imix table values
    sx2 = xtime[sx];
    e2 = xtime[e];
    e4 = xtime[e2];
    e8 = xtime[e4];
    me =
      (sx2 << 24) ^  // 2
      (sx << 16) ^   // 1
      (sx << 8) ^    // 1
      (sx ^ sx2);    // 3
    ime =
      (e2 ^ e4 ^ e8) << 24 ^  // E (14)
      (e ^ e8) << 16 ^        // 9
      (e ^ e4 ^ e8) << 8 ^    // D (13)
      (e ^ e2 ^ e8);          // B (11)
    // produce each of the mix tables by rotating the 2,1,1,3 value
    for(var n = 0; n < 4; ++n) {
      mix[n][e] = me;
      imix[n][sx] = ime;
      // cycle the right most byte to the left most position
      // ie: 2,1,1,3 becomes 3,2,1,1
      me = me << 24 | me >>> 8;
      ime = ime << 24 | ime >>> 8;
    }

    // get next element and inverse
    if(e === 0) {
      // 1 is the inverse of 1
      e = ei = 1;
    } else {
      // e = 2e + 2*2*2*(10e)) = multiply e by 82 (chosen generator)
      // ei = ei + 2*2*ei = multiply ei by 5 (inverse generator)
      e = e2 ^ xtime[xtime[xtime[e2 ^ e8]]];
      ei ^= xtime[xtime[ei]];
    }
  }
};

/**
 * Generates a key schedule using the AES key expansion algorithm.
 *
 * The AES algorithm takes the Cipher Key, K, and performs a Key Expansion
 * routine to generate a key schedule. The Key Expansion generates a total
 * of Nb*(Nr + 1) words: the algorithm requires an initial set of Nb words,
 * and each of the Nr rounds requires Nb words of key data. The resulting
 * key schedule consists of a linear array of 4-byte words, denoted [wi ],
 * with i in the range 0 ≤ i < Nb(Nr + 1).
 *
 * KeyExpansion(byte key[4*Nk], word w[Nb*(Nr+1)], Nk)
 * AES-128 (Nb=4, Nk=4, Nr=10)
 * AES-192 (Nb=4, Nk=6, Nr=12)
 * AES-256 (Nb=4, Nk=8, Nr=14)
 * Note: Nr=Nk+6.
 *
 * Nb is the number of columns (32-bit words) comprising the State (or
 * number of bytes in a block). For AES, Nb=4.
 *
 * @param key the key to schedule (as an array of 32-bit words).
 * @param decrypt true to modify the key schedule to decrypt, false not to.
 *
 * @return the generated key schedule.
 */
var expandKey = function(key, decrypt) {
  // copy the key's words to initialize the key schedule
  var w = key.slice(0);

  /* RotWord() will rotate a word, moving the first byte to the last
    byte's position (shifting the other bytes left).

    We will be getting the value of Rcon at i / Nk. 'i' will iterate
    from Nk to (Nb * Nr+1). Nk = 4 (4 byte key), Nb = 4 (4 words in
    a block), Nr = Nk + 6 (10). Therefore 'i' will iterate from
    4 to 44 (exclusive). Each time we iterate 4 times, i / Nk will
    increase by 1. We use a counter iNk to keep track of this.
   */

  // go through the rounds expanding the key
  var temp, iNk = 1;
  var Nk = w.length;
  var Nr1 = Nk + 6 + 1;
  var end = Nb * Nr1;
  for(var i = Nk; i < end; ++i) {
    temp = w[i - 1];
    if(i % Nk === 0) {
      // temp = SubWord(RotWord(temp)) ^ Rcon[i / Nk]
      temp =
        sbox[temp >>> 16 & 255] << 24 ^
        sbox[temp >>> 8 & 255] << 16 ^
        sbox[temp & 255] << 8 ^
        sbox[temp >>> 24] ^ (rcon[iNk] << 24);
      iNk++;
    } else if(Nk > 6 && (i % Nk === 4)) {
      // temp = SubWord(temp)
      temp =
        sbox[temp >>> 24] << 24 ^
        sbox[temp >>> 16 & 255] << 16 ^
        sbox[temp >>> 8 & 255] << 8 ^
        sbox[temp & 255];
    }
    w[i] = w[i - Nk] ^ temp;
  }

   /* When we are updating a cipher block we always use the code path for
     encryption whether we are decrypting or not (to shorten code and
     simplify the generation of look up tables). However, because there
     are differences in the decryption algorithm, other than just swapping
     in different look up tables, we must transform our key schedule to
     account for these changes:

     1. The decryption algorithm gets its key rounds in reverse order.
     2. The decryption algorithm adds the round key before mixing columns
       instead of afterwards.

     We don't need to modify our key schedule to handle the first case,
     we can just traverse the key schedule in reverse order when decrypting.

     The second case requires a little work.

     The tables we built for performing rounds will take an input and then
     perform SubBytes() and MixColumns() or, for the decrypt version,
     InvSubBytes() and InvMixColumns(). But the decrypt algorithm requires
     us to AddRoundKey() before InvMixColumns(). This means we'll need to
     apply some transformations to the round key to inverse-mix its columns
     so they'll be correct for moving AddRoundKey() to after the state has
     had its columns inverse-mixed.

     To inverse-mix the columns of the state when we're decrypting we use a
     lookup table that will apply InvSubBytes() and InvMixColumns() at the
     same time. However, the round key's bytes are not inverse-substituted
     in the decryption algorithm. To get around this problem, we can first
     substitute the bytes in the round key so that when we apply the
     transformation via the InvSubBytes()+InvMixColumns() table, it will
     undo our substitution leaving us with the original value that we
     want -- and then inverse-mix that value.

     This change will correctly alter our key schedule so that we can XOR
     each round key with our already transformed decryption state. This
     allows us to use the same code path as the encryption algorithm.

     We make one more change to the decryption key. Since the decryption
     algorithm runs in reverse from the encryption algorithm, we reverse
     the order of the round keys to avoid having to iterate over the key
     schedule backwards when running the encryption algorithm later in
     decryption mode. In addition to reversing the order of the round keys,
     we also swap each round key's 2nd and 4th rows. See the comments
     section where rounds are performed for more details about why this is
     done. These changes are done inline with the other substitution
     described above.
  */
  if(decrypt) {
    var tmp;
    var m0 = imix[0];
    var m1 = imix[1];
    var m2 = imix[2];
    var m3 = imix[3];
    var wnew = w.slice(0);
    end = w.length;
    for(var i = 0, wi = end - Nb; i < end; i += Nb, wi -= Nb) {
      // do not sub the first or last round key (round keys are Nb
      // words) as no column mixing is performed before they are added,
      // but do change the key order
      if(i === 0 || i === (end - Nb)) {
        wnew[i] = w[wi];
        wnew[i + 1] = w[wi + 3];
        wnew[i + 2] = w[wi + 2];
        wnew[i + 3] = w[wi + 1];
      } else {
        // substitute each round key byte because the inverse-mix
        // table will inverse-substitute it (effectively cancel the
        // substitution because round key bytes aren't sub'd in
        // decryption mode) and swap indexes 3 and 1
        for(var n = 0; n < Nb; ++n) {
          tmp = w[wi + n];
          wnew[i + (3&-n)] =
            m0[sbox[tmp >>> 24]] ^
            m1[sbox[tmp >>> 16 & 255]] ^
            m2[sbox[tmp >>> 8 & 255]] ^
            m3[sbox[tmp & 255]];
        }
      }
    }
    w = wnew;
  }

  return w;
};

/**
 * Updates a single block (16 bytes) using AES. The update will either
 * encrypt or decrypt the block.
 *
 * @param w the key schedule.
 * @param input the input block (an array of 32-bit words).
 * @param output the updated output block.
 * @param decrypt true to decrypt the block, false to encrypt it.
 */
var _updateBlock = function(w, input, output, decrypt) {
  /*
  Cipher(byte in[4*Nb], byte out[4*Nb], word w[Nb*(Nr+1)])
  begin
    byte state[4,Nb]
    state = in
    AddRoundKey(state, w[0, Nb-1])
    for round = 1 step 1 to Nr–1
      SubBytes(state)
      ShiftRows(state)
      MixColumns(state)
      AddRoundKey(state, w[round*Nb, (round+1)*Nb-1])
    end for
    SubBytes(state)
    ShiftRows(state)
    AddRoundKey(state, w[Nr*Nb, (Nr+1)*Nb-1])
    out = state
  end

  InvCipher(byte in[4*Nb], byte out[4*Nb], word w[Nb*(Nr+1)])
  begin
    byte state[4,Nb]
    state = in
    AddRoundKey(state, w[Nr*Nb, (Nr+1)*Nb-1])
    for round = Nr-1 step -1 downto 1
      InvShiftRows(state)
      InvSubBytes(state)
      AddRoundKey(state, w[round*Nb, (round+1)*Nb-1])
      InvMixColumns(state)
    end for
    InvShiftRows(state)
    InvSubBytes(state)
    AddRoundKey(state, w[0, Nb-1])
    out = state
  end
  */

  // Encrypt: AddRoundKey(state, w[0, Nb-1])
  // Decrypt: AddRoundKey(state, w[Nr*Nb, (Nr+1)*Nb-1])
  var Nr = w.length / 4 - 1;
  var m0, m1, m2, m3, sub;
  if(decrypt) {
    m0 = imix[0];
    m1 = imix[1];
    m2 = imix[2];
    m3 = imix[3];
    sub = isbox;
  } else {
    m0 = mix[0];
    m1 = mix[1];
    m2 = mix[2];
    m3 = mix[3];
    sub = sbox;
  }
  var a, b, c, d, a2, b2, c2;
  a = input[0] ^ w[0];
  b = input[decrypt ? 3 : 1] ^ w[1];
  c = input[2] ^ w[2];
  d = input[decrypt ? 1 : 3] ^ w[3];
  var i = 3;

  /* In order to share code we follow the encryption algorithm when both
    encrypting and decrypting. To account for the changes required in the
    decryption algorithm, we use different lookup tables when decrypting
    and use a modified key schedule to account for the difference in the
    order of transformations applied when performing rounds. We also get
    key rounds in reverse order (relative to encryption). */
  for(var round = 1; round < Nr; ++round) {
    /* As described above, we'll be using table lookups to perform the
      column mixing. Each column is stored as a word in the state (the
      array 'input' has one column as a word at each index). In order to
      mix a column, we perform these transformations on each row in c,
      which is 1 byte in each word. The new column for c0 is c'0:

               m0      m1      m2      m3
      r0,c'0 = 2*r0,c0 + 3*r1,c0 + 1*r2,c0 + 1*r3,c0
      r1,c'0 = 1*r0,c0 + 2*r1,c0 + 3*r2,c0 + 1*r3,c0
      r2,c'0 = 1*r0,c0 + 1*r1,c0 + 2*r2,c0 + 3*r3,c0
      r3,c'0 = 3*r0,c0 + 1*r1,c0 + 1*r2,c0 + 2*r3,c0

      So using mix tables where c0 is a word with r0 being its upper
      8 bits and r3 being its lower 8 bits:

      m0[c0 >> 24] will yield this word: [2*r0,1*r0,1*r0,3*r0]
      ...
      m3[c0 & 255] will yield this word: [1*r3,1*r3,3*r3,2*r3]

      Therefore to mix the columns in each word in the state we
      do the following (& 255 omitted for brevity):
      c'0,r0 = m0[c0 >> 24] ^ m1[c1 >> 16] ^ m2[c2 >> 8] ^ m3[c3]
      c'0,r1 = m0[c0 >> 24] ^ m1[c1 >> 16] ^ m2[c2 >> 8] ^ m3[c3]
      c'0,r2 = m0[c0 >> 24] ^ m1[c1 >> 16] ^ m2[c2 >> 8] ^ m3[c3]
      c'0,r3 = m0[c0 >> 24] ^ m1[c1 >> 16] ^ m2[c2 >> 8] ^ m3[c3]

      However, before mixing, the algorithm requires us to perform
      ShiftRows(). The ShiftRows() transformation cyclically shifts the
      last 3 rows of the state over different offsets. The first row
      (r = 0) is not shifted.

      s'_r,c = s_r,(c + shift(r, Nb) mod Nb
      for 0 < r < 4 and 0 <= c < Nb and
      shift(1, 4) = 1
      shift(2, 4) = 2
      shift(3, 4) = 3.

      This causes the first byte in r = 1 to be moved to the end of
      the row, the first 2 bytes in r = 2 to be moved to the end of
      the row, the first 3 bytes in r = 3 to be moved to the end of
      the row:

      r1: [c0 c1 c2 c3] => [c1 c2 c3 c0]
      r2: [c0 c1 c2 c3]    [c2 c3 c0 c1]
      r3: [c0 c1 c2 c3]    [c3 c0 c1 c2]

      We can make these substitutions inline with our column mixing to
      generate an updated set of equations to produce each word in the
      state (note the columns have changed positions):

      c0 c1 c2 c3 => c0 c1 c2 c3
      c0 c1 c2 c3    c1 c2 c3 c0  (cycled 1 byte)
      c0 c1 c2 c3    c2 c3 c0 c1  (cycled 2 bytes)
      c0 c1 c2 c3    c3 c0 c1 c2  (cycled 3 bytes)

      Therefore:

      c'0 = 2*r0,c0 + 3*r1,c1 + 1*r2,c2 + 1*r3,c3
      c'0 = 1*r0,c0 + 2*r1,c1 + 3*r2,c2 + 1*r3,c3
      c'0 = 1*r0,c0 + 1*r1,c1 + 2*r2,c2 + 3*r3,c3
      c'0 = 3*r0,c0 + 1*r1,c1 + 1*r2,c2 + 2*r3,c3

      c'1 = 2*r0,c1 + 3*r1,c2 + 1*r2,c3 + 1*r3,c0
      c'1 = 1*r0,c1 + 2*r1,c2 + 3*r2,c3 + 1*r3,c0
      c'1 = 1*r0,c1 + 1*r1,c2 + 2*r2,c3 + 3*r3,c0
      c'1 = 3*r0,c1 + 1*r1,c2 + 1*r2,c3 + 2*r3,c0

      ... and so forth for c'2 and c'3. The important distinction is
      that the columns are cycling, with c0 being used with the m0
      map when calculating c0, but c1 being used with the m0 map when
      calculating c1 ... and so forth.

      When performing the inverse we transform the mirror image and
      skip the bottom row, instead of the top one, and move upwards:

      c3 c2 c1 c0 => c0 c3 c2 c1  (cycled 3 bytes) *same as encryption
      c3 c2 c1 c0    c1 c0 c3 c2  (cycled 2 bytes)
      c3 c2 c1 c0    c2 c1 c0 c3  (cycled 1 byte)  *same as encryption
      c3 c2 c1 c0    c3 c2 c1 c0

      If you compare the resulting matrices for ShiftRows()+MixColumns()
      and for InvShiftRows()+InvMixColumns() the 2nd and 4th columns are
      different (in encrypt mode vs. decrypt mode). So in order to use
      the same code to handle both encryption and decryption, we will
      need to do some mapping.

      If in encryption mode we let a=c0, b=c1, c=c2, d=c3, and r<N> be
      a row number in the state, then the resulting matrix in encryption
      mode for applying the above transformations would be:

      r1: a b c d
      r2: b c d a
      r3: c d a b
      r4: d a b c

      If we did the same in decryption mode we would get:

      r1: a d c b
      r2: b a d c
      r3: c b a d
      r4: d c b a

      If instead we swap d and b (set b=c3 and d=c1), then we get:

      r1: a b c d
      r2: d a b c
      r3: c d a b
      r4: b c d a

      Now the 1st and 3rd rows are the same as the encryption matrix. All
      we need to do then to make the mapping exactly the same is to swap
      the 2nd and 4th rows when in decryption mode. To do this without
      having to do it on each iteration, we swapped the 2nd and 4th rows
      in the decryption key schedule. We also have to do the swap above
      when we first pull in the input and when we set the final output. */
    a2 =
      m0[a >>> 24] ^
      m1[b >>> 16 & 255] ^
      m2[c >>> 8 & 255] ^
      m3[d & 255] ^ w[++i];
    b2 =
      m0[b >>> 24] ^
      m1[c >>> 16 & 255] ^
      m2[d >>> 8 & 255] ^
      m3[a & 255] ^ w[++i];
    c2 =
      m0[c >>> 24] ^
      m1[d >>> 16 & 255] ^
      m2[a >>> 8 & 255] ^
      m3[b & 255] ^ w[++i];
    d =
      m0[d >>> 24] ^
      m1[a >>> 16 & 255] ^
      m2[b >>> 8 & 255] ^
      m3[c & 255] ^ w[++i];
    a = a2;
    b = b2;
    c = c2;
  }

  /*
    Encrypt:
    SubBytes(state)
    ShiftRows(state)
    AddRoundKey(state, w[Nr*Nb, (Nr+1)*Nb-1])

    Decrypt:
    InvShiftRows(state)
    InvSubBytes(state)
    AddRoundKey(state, w[0, Nb-1])
   */
   // Note: rows are shifted inline
  output[0] =
    (sub[a >>> 24] << 24) ^
    (sub[b >>> 16 & 255] << 16) ^
    (sub[c >>> 8 & 255] << 8) ^
    (sub[d & 255]) ^ w[++i];
  output[decrypt ? 3 : 1] =
    (sub[b >>> 24] << 24) ^
    (sub[c >>> 16 & 255] << 16) ^
    (sub[d >>> 8 & 255] << 8) ^
    (sub[a & 255]) ^ w[++i];
  output[2] =
    (sub[c >>> 24] << 24) ^
    (sub[d >>> 16 & 255] << 16) ^
    (sub[a >>> 8 & 255] << 8) ^
    (sub[b & 255]) ^ w[++i];
  output[decrypt ? 1 : 3] =
    (sub[d >>> 24] << 24) ^
    (sub[a >>> 16 & 255] << 16) ^
    (sub[b >>> 8 & 255] << 8) ^
    (sub[c & 255]) ^ w[++i];
};

/**
 * Creates an AES cipher object. CBC (cipher-block-chaining) mode will be
 * used by default, the other supported modes are: CFB, OFB, and CTR.
 *
 * The key and iv may be given as a string of bytes, an array of bytes, a
 * byte buffer, or an array of 32-bit words. If an iv is provided, then
 * encryption/decryption will be started, otherwise start() must be called
 * with an iv.
 *
 * @param options the options to use.
 *          key the symmetric key to use.
 *          iv the initialization vector to start with, null not to start.
 *          output the buffer to write to.
 *          decrypt true for decryption, false for encryption.
 *          mode the cipher mode to use (default: 'CBC').
 *
 * @return the cipher.
 */
var _createCipher = function(options) {
  // TODO: abstract block cipher into its own file, reuse for aes, 3des, etc.
  // called "blockCipher.js"
  // TODO: abstract modes into their own file(s) (or just one for all modes)
  // called "blockCipherModes.js" (currently far too many detail-leaks)
  var cipher = null;

  if(!init) {
    initialize();
  }

  var key = options.key;
  var iv = options.iv;
  var output = options.output;
  var decrypt = options.decrypt;
  var mode = options.mode;

  // default to CBC mode
  mode = (mode || 'CBC').toUpperCase();

  /* Note: The key may be a string of bytes, an array of bytes, a byte
    buffer, or an array of 32-bit integers. If the key is in bytes, then
    it must be 16, 24, or 32 bytes in length. If it is in 32-bit
    integers, it must be 4, 6, or 8 integers long. */

  if(typeof key === 'string' &&
    (key.length === 16 || key.length === 24 || key.length === 32)) {
    // convert key string into byte buffer
    key = forge.util.createBuffer(key);
  } else if(forge.util.isArray(key) &&
    (key.length === 16 || key.length === 24 || key.length === 32)) {
    // convert key integer array into byte buffer
    var tmp = key;
    key = forge.util.createBuffer();
    for(var i = 0; i < tmp.length; ++i) {
      key.putByte(tmp[i]);
    }
  }

  // convert key byte buffer into 32-bit integer array
  if(!forge.util.isArray(key)) {
    var tmp = key;
    key = [];

    // key lengths of 16, 24, 32 bytes allowed
    var len = tmp.length();
    if(len === 16 || len === 24 || len === 32) {
      len = len >>> 2;
      for(var i = 0; i < len; ++i) {
        key.push(tmp.getInt32());
      }
    }
  }

  // key must be an array of 32-bit integers by now
  if(!forge.util.isArray(key) ||
    !(key.length === 4 || key.length === 6 || key.length === 8)) {
    return cipher;
  }

  // (CFB/OFB/CTR/GCM always uses encryption)
  var alwaysEncrypt = (['CFB', 'OFB', 'CTR', 'GCM'].indexOf(mode) !== -1);

  // CBC mode requires padding
  var requirePadding = (mode === 'CBC');

  // private vars for state
  var _w = expandKey(key, decrypt && !alwaysEncrypt);
  var _blockSize = Nb << 2;
  var _input;
  var _output;
  var _inBlock;
  var _outBlock;
  var _tmpBlock;
  var _prev;
  var _finish;
  var _op;
  var _r;
  var _hashSubkey;
  var _m;
  var _j0;
  var _s;
  var _tag;
  var _aDataLength;
  var _cLength;
  var _tagLength;
  cipher = {
    // output from AES (either encrypted or decrypted bytes)
    output: null
  };

  if(mode === 'CBC') {
    _op = decrypt ? cbcDecryptOp : cbcEncryptOp;
  } else if(mode === 'CFB') {
    _op = cfbOp;
  } else if(mode === 'OFB') {
    _op = ofbOp;
  } else if(mode === 'CTR') {
    _op = ctrOp;
  } else if(mode === 'GCM') {
    _op = decrypt ? gcmDecryptOp : gcmEncryptOp;
    // authentication tag output
    cipher.tag = null;
  } else {
    throw {
      message: 'Unsupported block cipher mode of operation: "' + mode + '"'
    };
  }

  /**
   * Updates the next block according to the cipher mode.
   *
   * @param input the buffer to read from.
   */
  cipher.update = function(input) {
    if(!_finish) {
      // not finishing, so fill the input buffer with more input
      _input.putBuffer(input);
    }

    // do cipher operation while input contains full blocks or if finishing
    while(_input.length() >= _blockSize || (_input.length() > 0 && _finish)) {
      _op();
    }
  };

  /**
   * Finishes encrypting or decrypting.
   *
   * @param pad a padding function to use in CBC mode, null for default,
   *          signature(blockSize, buffer, decrypt).
   *
   * @return true if successful, false on error.
   */
  cipher.finish = function(pad) {
    var rval = true;

    // get # of bytes that won't fill a block
    var overflow = _input.length() % _blockSize;

    if(!decrypt) {
      if(pad) {
        rval = pad(_blockSize, _input, decrypt);
      } else if(requirePadding) {
        // add PKCS#7 padding to block (each pad byte is the
        // value of the number of pad bytes)
        var padding = (_input.length() === _blockSize) ?
          _blockSize : (_blockSize - _input.length());
        _input.fillWithByte(padding, padding);
      }
    }

    if(rval) {
      // do final update
      _finish = true;
      cipher.update();
    }

    if(decrypt) {
      if(requirePadding) {
        // check for error: input data not a multiple of blockSize
        rval = (overflow === 0);
      }
      if(rval) {
        if(pad) {
          rval = pad(_blockSize, _output, decrypt);
        } else if(requirePadding) {
          // ensure padding byte count is valid
          var len = _output.length();
          var count = _output.at(len - 1);
          if(count > (Nb << 2)) {
            rval = false;
          } else {
            // trim off padding bytes
            _output.truncate(count);
          }
        }
      }
    }

    // handle stream mode truncation if padding not set
    if(!requirePadding && !pad && overflow > 0) {
      _output.truncate(_blockSize - overflow);
    }

    // if using GCM mode, handle authentication tag
    if(mode === 'GCM') {
      // concatenate additional data length with cipher length
      var lengths = _aDataLength.concat(from64To32(_cLength * 8));

      // include lengths in hash
      _s = ghash(_hashSubkey, _s, lengths);

      // do GCTR(J_0, S)
      var tag = [];
      _updateBlock(_w, _j0, tag, false);
      for(var i = 0; i < Nb; ++i) {
        cipher.tag.putInt32(_s[i] ^ tag[i]);
      }

      // trim tag to length
      cipher.tag.truncate(cipher.tag.length() % (_tagLength / 8));

      // check authentication tag
      if(decrypt && cipher.tag.bytes() !== _tag) {
        rval = false;
      }
    }

    return rval;
  };

  /**
   * Starts or restarts the encryption or decryption process, whichever
   * was previously configured.
   *
   * For non-GCM mode, the IV may be a binary-encoded string of bytes, an array
   * of bytes, a byte buffer, or an array of 32-bit integers. If the IV is in
   * bytes, then it must be Nb (16) bytes in length. If the IV is given in as
   * 32-bit integers, then it must be 4 integers long.
   *
   * For GCM-mode, the IV must be given as a binary-encoded string of bytes or
   * a byte buffer. The number of bytes should be 12 (96 bits) as recommended
   * by NIST SP-800-38D but another length may be given.
   *
   * @param iv the initialization vector to use as a binary-encoded string of
   *          bytes, null to reuse the last ciphered block from a previous
   *          update().
   * @param options the options to use:
   *          additionalData additional authentication data as a binary-encoded
   *            string of bytes, for 'GCM' mode, (default: none).
   *          tagLength desired length of authentication tag, in bits, for
   *            'GCM' mode (0-128, default: 128).
   *          tag the authentication tag to check if decrypting, as a
   *             binary-encoded string of bytes.
   *          output the output the buffer to write to, null to create one.
   */
  cipher.start = function(iv, options) {
    // if IV is null, reuse block from previous encryption/decryption
    if(iv === null) {
      iv = _prev.slice(0);
    }

    // backwards compatibility: support second arg as output buffer
    var output = null;
    if(options instanceof forge.util.ByteBuffer) {
      output = options;
      options = {};
    }
    options = options || {};

    // TODO: abstract IV handling to cipher mode
    var ivLength;
    if(typeof iv === 'string') {
      // convert iv string into byte buffer
      iv = forge.util.createBuffer(iv);
    }

    if(mode !== 'GCM') {
      ivLength = _blockSize;
      if(forge.util.isArray(iv) && iv.length > 4) {
        // convert iv byte array into byte buffer
        var tmp = iv;
        iv = forge.util.createBuffer();
        for(var i = 0; i < iv.length; ++i) {
          iv.putByte(tmp[i]);
        }
      }
      if(!forge.util.isArray(iv)) {
        // convert iv byte buffer into 32-bit integer array
        iv = [iv.getInt32(), iv.getInt32(), iv.getInt32(), iv.getInt32()];
      }
    }

    // set private vars
    _input = forge.util.createBuffer();
    _output = output || forge.util.createBuffer();
    _inBlock = new Array(Nb);
    _outBlock = new Array(Nb);
    _finish = false;
    cipher.output = _output;
    cipher.tag = forge.util.createBuffer();

    // CFB/OFB/CTR uses IV as first input
    if(['CFB', 'OFB', 'CTR'].indexOf(mode) !== -1) {
      for(var i = 0; i < Nb; ++i) {
        _inBlock[i] = iv[i];
      }
    } else if(mode === 'CBC') {
      // save IV as "previous" block
      _prev = iv.slice(0);
    } else if(mode === 'GCM') {
      // no cipher data yet
      _cLength = 0;

      // R is actually this value concatenated with 120 more zero bits, but
      // we only XOR against R so the other zeros have no effect -- we just
      // apply this value to the first integer in a block
      _r = 0xE1000000;

      // default additional data is none
      var additionalData;
      if('additionalData' in options) {
        additionalData = forge.util.createBuffer(options.additionalData);
      } else {
        additionalData = forge.util.createBuffer();
      }

      // default tag length is 128 bits
      if('tagLength' in options) {
        _tagLength = options.tagLength;
      } else {
        _tagLength = 128;
      }

      if(decrypt) {
        // save tag to check later, create tmp storage for hash calculation
        _tag = forge.util.createBuffer(options.tag).getBytes();
        _tmpBlock = new Array(Nb);
      }

      // generate hash subkey
      // (apply block cipher to "zero" block)
      _hashSubkey = new Array(Nb);
      _updateBlock(_w, [0, 0, 0, 0], _hashSubkey, false);

      // generate table M
      // use 4-bit tables (32 component decomposition of a 16 byte value)
      // 8-bit tables take more space and are known to have security
      // vulnerabilities (in native implementations)
      var componentBits = 4;
      _m = generateHashTable(_hashSubkey, componentBits);

      // Note: support IV length different from 96 bits? (only supporting
      // 96 bits is recommended by NIST SP-800-38D)
      // generate J_0
      ivLength = iv.length();
      if(ivLength === 12) {
        // 96-bit IV
        _j0 = [iv.getInt32(), iv.getInt32(), iv.getInt32(), 1];
      } else {
        // IV is NOT 96-bits
        _j0 = [0, 0, 0, 0];
        while(iv.length() > 0) {
          _j0 = ghash(
            _hashSubkey, _j0,
            [iv.getInt32(), iv.getInt32(), iv.getInt32(), iv.getInt32()]);
        }
        _j0 = ghash(_hashSubkey, _j0, [0, 0].concat(from64To32(ivLength * 8)));
      }

      // generate ICB (initial counter block)
      _inBlock = _j0.slice(0);
      inc32(_inBlock);

      // consume authentication data
      additionalData = forge.util.createBuffer(additionalData);
      // save additional data length as a BE 64-bit number
      _aDataLength = from64To32(additionalData.length() * 8);
      // pad additional data to 128 bit (16 byte) block size
      var overflow = additionalData.length() % _blockSize;
      if(overflow) {
        additionalData.fillWithByte(0, _blockSize - overflow);
      }
      _s = [0, 0, 0, 0];
      while(additionalData.length() > 0) {
        _s = ghash(_hashSubkey, _s, [
          additionalData.getInt32(),
          additionalData.getInt32(),
          additionalData.getInt32(),
          additionalData.getInt32()
        ]);
      }
    }
  };
  if(iv !== null) {
    cipher.start(iv, output);
  }
  return cipher;

  // block cipher mode operations:

  function cbcEncryptOp() {
    // get next block
    // CBC XOR's IV (or previous block) with plaintext
    for(var i = 0; i < Nb; ++i) {
      _inBlock[i] = _prev[i] ^ _input.getInt32();
    }

    // update block
    _updateBlock(_w, _inBlock, _outBlock, decrypt);

    // write output, save previous block
    for(var i = 0; i < Nb; ++i) {
      _output.putInt32(_outBlock[i]);
    }
    _prev = _outBlock;
  }

  function cbcDecryptOp() {
    // get next block
    for(var i = 0; i < Nb; ++i) {
      _inBlock[i] = _input.getInt32();
    }

    // update block
    _updateBlock(_w, _inBlock, _outBlock, decrypt);

    // write output, save previous ciphered block
    // CBC XOR's IV (or previous block) with ciphertext
    for(var i = 0; i < Nb; ++i) {
      _output.putInt32(_prev[i] ^ _outBlock[i]);
    }
    _prev = _inBlock.slice(0);
  }

  function cfbOp() {
    // update block (CFB always uses encryption mode)
    _updateBlock(_w, _inBlock, _outBlock, false);

    // XOR input with output
    for(var i = 0; i < Nb; ++i) {
      _inBlock[i] = _input.getInt32();
      var result = _inBlock[i] ^ _outBlock[i];
      if(!decrypt) {
        // update next input block when encrypting
        _inBlock[i] = result;
      }
      _output.putInt32(result);
    }
  }

  function ofbOp() {
    // update block (OFB always uses encryption mode)
    _updateBlock(_w, _inBlock, _outBlock, false);

    // XOR input with output and update next input
    for(var i = 0; i < Nb; ++i) {
      _output.putInt32(_input.getInt32() ^ _outBlock[i]);
      _inBlock[i] = _outBlock[i];
    }
  }

  function ctrOp() {
    // update block (CTR always uses encryption mode)
    _updateBlock(_w, _inBlock, _outBlock, false);

    // increment counter (input block)
    inc32(_inBlock);

    // XOR input with output
    for(var i = 0; i < Nb; ++i) {
      _output.putInt32(_input.getInt32() ^ _outBlock[i]);
    }
  }

  function gcmEncryptOp() {
    // update block (GCM always uses encryption mode)
    _updateBlock(_w, _inBlock, _outBlock, false);

    // increment counter (input block)
    inc32(_inBlock);

    // save input length
    var inputLength = _input.length();

    // XOR input with output
    for(var i = 0; i < Nb; ++i) {
      _outBlock[i] ^= _input.getInt32();
    }

    // handle overflow
    if(inputLength < _blockSize) {
      // get block overflow
      var overflow = inputLength % _blockSize;
      _cLength += overflow;

      // truncate for hash function
      var tmp = forge.util.createBuffer();
      tmp.putInt32(_outBlock[0]);
      tmp.putInt32(_outBlock[1]);
      tmp.putInt32(_outBlock[2]);
      tmp.putInt32(_outBlock[3]);
      tmp.truncate(_blockSize - overflow);
      _outBlock[0] = tmp.getInt32();
      _outBlock[1] = tmp.getInt32();
      _outBlock[2] = tmp.getInt32();
      _outBlock[3] = tmp.getInt32();
    } else {
      _cLength += _blockSize;
    }

    for(var i = 0; i < Nb; ++i) {
      _output.putInt32(_outBlock[i]);
    }

    // update hash block S
    _s = ghash(_hashSubkey, _s, _outBlock);
  }

  function gcmDecryptOp() {
    // update block (GCM always uses encryption mode)
    _updateBlock(_w, _inBlock, _outBlock, false);

    // increment counter (input block)
    inc32(_inBlock);

    // save input length
    var inputLength = _input.length();

    // update hash block S
    _tmpBlock[0] = _input.getInt32();
    _tmpBlock[1] = _input.getInt32();
    _tmpBlock[2] = _input.getInt32();
    _tmpBlock[3] = _input.getInt32();
    _s = ghash(_hashSubkey, _s, _tmpBlock);

    // XOR input with output
    for(var i = 0; i < Nb; ++i) {
      _output.putInt32(_outBlock[i] ^ _tmpBlock[i]);
    }

    // handle overflow
    if(inputLength < _blockSize) {
      _cLength += inputLength % _blockSize;

      // Note: truncation currently handled by cipher.finish()
      //_output.truncate(_blockSize - (inputLength % _blockSize));
    } else {
      _cLength += _blockSize;
    }
  }

  function inc32(block) {
    // increment last 32 bits of block only
    block[Nb - 1] = (block[Nb - 1] + 1) & 0xFFFFFFFF;
  }

  function from64To32(num) {
    // convert 64-bit number to two BE Int32s
    return [Math.floor(num / 0x100000000), num & 0xFFFFFFFF];
  }

  /**
   * See NIST SP-800-38D 6.3 (Algorithm 1). This function performs Galois
   * field multiplication. The field, GF(2^128), is defined by the polynomial:
   *
   * x^128 + x^7 + x^2 + x + 1
   *
   * Which is represented in little-endian binary form as: 11100001 (0xe1). When
   * the value of a coefficient is 1, a bit is set. The value R, is the
   * concatenation of this value and 120 zero bits, yielding a 128-bit value
   * which matches the block size.
   *
   * This function will multiply two elements (vectors of bytes), X and Y, in
   * the field GF(2^128). The result is initialized to zero. For each bit of
   * X (out of 128), x_i, if x_i is set, then the result is multiplied (XOR'd)
   * by the current value of Y. For each bit, the value of Y will be raised by
   * a power of x (multiplied by the polynomial x). This can be achieved by
   * shifting Y once to the right. If the current value of Y, prior to being
   * multiplied by x, has 0 as its LSB, then it is a 127th degree polynomial.
   * Otherwise, we must divide by R after shifting to find the remainder.
   *
   * @param x the first block to multiply by the second.
   * @param y the second block to multiply by the first.
   *
   * @return the block result of the multiplication.
   */
  function gcmMultiply(x, y) {
    var z_i = [0, 0, 0, 0];
    var v_i = y.slice(0);

    // calculate Z_128 (block has 128 bits)
    for(var i = 0; i < 128; ++i) {
      // if x_i is 0, Z_{i+1} = Z_i (unchanged)
      // else Z_{i+1} = Z_i ^ V_i
      // get x_i by finding 32-bit int position, then left shift 1 by remainder
      var x_i = x[Math.floor(i / 32)] & (1 << (31 - i % 32));
      if(x_i) {
        z_i[0] ^= v_i[0];
        z_i[1] ^= v_i[1];
        z_i[2] ^= v_i[2];
        z_i[3] ^= v_i[3];
      }

      gcmPow(v_i, v_i);
    }

    return z_i;
  }

  /**
   * Precomputes a table for multiplying against the hash subkey. This
   * mechanism provides a substantial speed increase over multiplication
   * performed without a table. The table-based multiplication this table is
   * for solves X * H by multiplying each component of X by H and then
   * composing the results together using XOR.
   *
   * This function can be used to generate tables with different bit sizes
   * for the components, however, this implementation assumes there are
   * 32 components of X (which is a 16 byte vector), therefore each component
   * takes 4-bits (so the table is constructed with bits=4).
   *
   * @param h the hash subkey.
   * @param bits the bit size for a component.
   */
  function generateHashTable(h, bits) {
    // TODO: There are further optimizations that would use only the
    // first table M_0 (or some variant) along with a remainder table;
    // this can be explored in the future
    var multiplier = 8 / bits;
    var perInt = 4 * multiplier;
    var size = 16 * multiplier;
    var m = new Array(size);
    for(var i = 0; i < size; ++i) {
      var tmp = [0, 0, 0, 0];
      var idx = Math.floor(i / perInt);
      var shft = ((perInt - 1 - (i % perInt)) * bits);
      tmp[idx] = (1 << (bits - 1)) << shft;
      m[i] = generateSubHashTable(gcmMultiply(tmp, h), bits);
    }
    return m;
  }

  /**
   * Generates a table for multiplying against the hash subkey for one
   * particular component (out of all possible component values).
   *
   * @param mid the pre-multiplied value for the middle key of the table.
   * @param bits the bit size for a component.
   */
  function generateSubHashTable(mid, bits) {
    // compute the table quickly by minimizing the number of
    // POW operations -- they only need to be performed for powers of 2,
    // all other entries can be composed from those powers using XOR
    var size = 1 << bits;
    var half = size >>> 1;
    var m = new Array(size);
    m[half] = mid.slice(0);
    var i = half >>> 1;
    while(i > 0) {
      // raise m0[2 * i] and store in m0[i]
      gcmPow(m[2 * i], m[i] = []);
      i >>= 1;
    }
    i = 2;
    while(i < half) {
      for(var j = 1; j < i; ++j) {
        var m_i = m[i];
        var m_j = m[j];
        m[i + j] = [
          m_i[0] ^ m_j[0],
          m_i[1] ^ m_j[1],
          m_i[2] ^ m_j[2],
          m_i[3] ^ m_j[3]
        ];
      }
      i *= 2;
    }
    m[0] = [0, 0, 0, 0];
    /* Note: We could avoid storing these by doing composition during multiply
    calculate top half using composition by speed is preferred. */
    for(i = half + 1; i < size; ++i) {
      var c = m[i ^ half];
      m[i] = [mid[0] ^ c[0], mid[1] ^ c[1], mid[2] ^ c[2], mid[3] ^ c[3]];
    }
    return m;
  }

  function gcmPow(x, out) {
    // if LSB(x) is 1, x = x >>> 1
    // else x = (x >>> 1) ^ R
    var lsb = x[3] & 1;

    // always do x >>> 1:
    // starting with the rightmost integer, shift each integer to the right
    // one bit, pulling in the bit from the integer to the left as its top
    // most bit (do this for the last 3 integers)
    for(var i = 3; i > 0; --i) {
      out[i] = (x[i] >>> 1) | ((x[i - 1] & 1) << 31);
    }
    // shift the first integer normally
    out[0] = x[0] >>> 1;

    // if lsb was not set, then polynomial had a degree of 127 and doesn't
    // need to divided; otherwise, XOR with R to find the remainder; we only
    // need to XOR the first integer since R technically ends w/120 zero bits
    if(lsb) {
      out[0] ^= _r;
    }
  }

  function gcmHashMultiply(x) {
    // assumes 4-bit tables are used
    var z = [0, 0, 0, 0];
    for(var i = 0; i < 32; ++i) {
      var idx = Math.floor(i / 8);
      var x_i = (x[idx] >>> ((7 - (i % 8)) * 4)) & 0xF;
      var ah = _m[i][x_i];
      z[0] ^= ah[0];
      z[1] ^= ah[1];
      z[2] ^= ah[2];
      z[3] ^= ah[3];
    }
    return z;
  }

  /**
   * A continuing version of the GHASH algorithm that operates on a single
   * block. The hash block, last hash value (Ym) and the new block to hash
   * are given.
   *
   * @param h the hash block.
   * @param y the previous value for Ym, use [0, 0, 0, 0] for a new hash.
   * @param x the block to hash.
   *
   * @return the hashed value (Ym).
   */
  function ghash(h, y, x) {
    y[0] ^= x[0];
    y[1] ^= x[1];
    y[2] ^= x[2];
    y[3] ^= x[3];
    return gcmHashMultiply(y);
    //return gcmMultiply(y, h);
  }
};

/* AES API */
forge.aes = forge.aes || {};

/**
 * Creates an AES cipher object to encrypt data using the given symmetric key.
 * The output will be stored in the 'output' member of the returned cipher.
 *
 * The key and iv may be given as a string of bytes, an array of bytes,
 * a byte buffer, or an array of 32-bit words.
 *
 * @param key the symmetric key to use.
 * @param iv the initialization vector to use.
 * @param output the buffer to write to, null to create one.
 * @param mode the cipher mode to use (default: 'CBC').
 *
 * @return the cipher.
 */
forge.aes.startEncrypting = function(key, iv, output, mode) {
  return _createCipher({
    key: key,
    iv: iv,
    output: output,
    decrypt: false,
    mode: mode
  });
};

/**
 * Creates an AES cipher object to encrypt data using the given symmetric key.
 *
 * The key may be given as a string of bytes, an array of bytes, a
 * byte buffer, or an array of 32-bit words.
 *
 * To start encrypting call start() on the cipher with an iv and optional
 * output buffer.
 *
 * @param key the symmetric key to use.
 * @param mode the cipher mode to use (default: 'CBC').
 *
 * @return the cipher.
 */
forge.aes.createEncryptionCipher = function(key, mode) {
  return _createCipher({
    key: key,
    iv: null,
    output: null,
    decrypt: false,
    mode: mode
  });
};

/**
 * Creates an AES cipher object to decrypt data using the given symmetric key.
 * The output will be stored in the 'output' member of the returned cipher.
 *
 * The key and iv may be given as a string of bytes, an array of bytes,
 * a byte buffer, or an array of 32-bit words.
 *
 * @param key the symmetric key to use.
 * @param iv the initialization vector to use.
 * @param output the buffer to write to, null to create one.
 * @param mode the cipher mode to use (default: 'CBC').
 *
 * @return the cipher.
 */
forge.aes.startDecrypting = function(key, iv, output, mode) {
  return _createCipher({
    key: key,
    iv: iv,
    output: output,
    decrypt: true,
    mode: mode
  });
};

/**
 * Creates an AES cipher object to decrypt data using the given symmetric key.
 *
 * The key may be given as a string of bytes, an array of bytes, a
 * byte buffer, or an array of 32-bit words.
 *
 * To start decrypting call start() on the cipher with an iv and
 * optional output buffer.
 *
 * @param key the symmetric key to use.
 * @param mode the cipher mode to use (default: 'CBC').
 *
 * @return the cipher.
 */
forge.aes.createDecryptionCipher = function(key, mode) {
  return _createCipher({
    key: key,
    iv: null,
    output: null,
    decrypt: true,
    mode: mode
  });
};

/**
 * Expands a key. Typically only used for testing.
 *
 * @param key the symmetric key to expand, as an array of 32-bit words.
 * @param decrypt true to expand for decryption, false for encryption.
 *
 * @return the expanded key.
 */
forge.aes._expandKey = function(key, decrypt) {
  if(!init) {
    initialize();
  }
  return expandKey(key, decrypt);
};

/**
 * Updates a single block. Typically only used for testing.
 *
 * @param w the expanded key to use.
 * @param input an array of block-size 32-bit words.
 * @param output an array of block-size 32-bit words.
 * @param decrypt true to decrypt, false to encrypt.
 */
forge.aes._updateBlock = _updateBlock;

} // end module implementation

/* ########## Begin module wrapper ########## */
var name = 'aes';
if(typeof define !== 'function') {
  // NodeJS -> AMD
  if(typeof module === 'object' && module.exports) {
    var nodeJS = true;
    define = function(ids, factory) {
      factory(require, module);
    };
  } else {
    // <script>
    if(typeof forge === 'undefined') {
      forge = {};
    }
    return initModule(forge);
  }
}
// AMD
var deps;
var defineFunc = function(require, module) {
  module.exports = function(forge) {
    var mods = deps.map(function(dep) {
      return require(dep);
    }).concat(initModule);
    // handle circular dependencies
    forge = forge || {};
    forge.defined = forge.defined || {};
    if(forge.defined[name]) {
      return forge[name];
    }
    forge.defined[name] = true;
    for(var i = 0; i < mods.length; ++i) {
      mods[i](forge);
    }
    return forge[name];
  };
};
var tmpDefine = define;
define = function(ids, factory) {
  deps = (typeof ids === 'string') ? factory.slice(2) : ids.slice(2);
  if(nodeJS) {
    delete define;
    return tmpDefine.apply(null, Array.prototype.slice.call(arguments, 0));
  }
  define = tmpDefine;
  return define.apply(null, Array.prototype.slice.call(arguments, 0));
};
define(['require', 'module', './util'], function() {
  defineFunc.apply(null, Array.prototype.slice.call(arguments, 0));
});
})();
