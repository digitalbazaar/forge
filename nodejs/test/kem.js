(function() {

function Tests(ASSERT, KEM, MD, RSA, UTIL, JSBN, RANDOM) {

  function FixedSecureRandom(str) {
    var _str = UTIL.hexToBytes(str);
    var index = 0;


    this.getBytes = this.getBytesSync = function(count, callback) {
      var r = _str.substr(index,count);

      index += count;

      return r;
    }
  }

  describe('kem', function() {
    it('should encrypt and decrypt', function() {
      var kdf = new KEM.kdf1(MD.sha256.create());
      var kem = KEM.rsa.create(kdf);

      var pair = RSA.generateKeyPair(512);

      var result = kem.encrypt(pair.publicKey, 256);
      var key1 = result.key;

      var key2 = kem.decrypt(pair.privateKey, result.ciphertext, 256);

      ASSERT.equal(key1, key2);
    });
  });

  /**
   * According to section "C.6 Test vectors for RSA-KEM" from ISO-18033-2 final
   * draft
   */
  describe('RsaKeyEncapsulationTestVectors', function() {
    // C.6.1
    it('Test 1', function() {

      var n = '5888113332502691251761936431009284884966640757179802337490546478326238537107326596800820237597139824869184990638749556269785797065508097452399642780486933';
      var e = '65537';
      var d = '3202313555859948186315374524474173995679783580392140237044349728046479396037520308981353808895461806395564474639124525446044708705259675840210989546479265';

      var C0 = '4603e5324cab9cef8365c817052d954d44447b1667099edc69942d32cd594e4ffcf268ae3836e2c35744aaa53ae201fe499806b67dedaa26bf72ecbd117a6fc0';
      var K = '5f8de105b5e96b2e490ddecbd147dd1def7e3b8e0e6a26eb7b956ccb8b3bdc1ca975bc57c3989e8fbad31a224655d800c46954840ff32052cdf0d640562bdfadfa263cfccf3c52b29f2af4a1869959bc77f854cf15bd7a25192985a842dbff8e13efee5b7e7e55bbe4d389647c686a9a9ab3fb889b2d7767d3837eea4e0a2f04';

      var kdf = new KEM.kdf1(MD.sha1.create());

      var rnd = new FixedSecureRandom('032e45326fa859a72ec235acff929b15d1372e30b207255f0611b8f785d764374152e0ac009e509e7ba30cd2f1778e113b64e135cf4e2292c75efe5288edfda4');

      var kem = KEM.rsa.create(kdf, {rng: rnd});

      var rsaPublicKey = RSA.setPublicKey(new JSBN.BigInteger(n), new JSBN.BigInteger(e));
      var rsaPrivateKey = RSA.setPrivateKey(new JSBN.BigInteger(n),null , new JSBN.BigInteger(d));

      var result = kem.encrypt(rsaPublicKey, 128);
      ASSERT.equal(UTIL.bytesToHex(result.ciphertext), C0);
      ASSERT.equal(UTIL.bytesToHex(result.key), K);

      var decryptedKey = kem.decrypt(rsaPrivateKey, result.ciphertext, 128);
      ASSERT.equal(UTIL.bytesToHex(decryptedKey), K);

    });

    // C.6.2
    it('Test 2', function() {

      var n = '5888113332502691251761936431009284884966640757179802337490546478326238537107326596800820237597139824869184990638749556269785797065508097452399642780486933';
      var e = '65537';
      var d = '3202313555859948186315374524474173995679783580392140237044349728046479396037520308981353808895461806395564474639124525446044708705259675840210989546479265';

      var C0 = '4603e5324cab9cef8365c817052d954d44447b1667099edc69942d32cd594e4ffcf268ae3836e2c35744aaa53ae201fe499806b67dedaa26bf72ecbd117a6fc0';
      var K = '0e6a26eb7b956ccb8b3bdc1ca975bc57c3989e8fbad31a224655d800c46954840ff32052cdf0d640562bdfadfa263cfccf3c52b29f2af4a1869959bc77f854cf15bd7a25192985a842dbff8e13efee5b7e7e55bbe4d389647c686a9a9ab3fb889b2d7767d3837eea4e0a2f04b53ca8f50fb31225c1be2d0126c8c7a4753b0807';

      var kdf = new KEM.kdf2(MD.sha1.create());

      var rnd = new FixedSecureRandom('032e45326fa859a72ec235acff929b15d1372e30b207255f0611b8f785d764374152e0ac009e509e7ba30cd2f1778e113b64e135cf4e2292c75efe5288edfda4');

      var kem = KEM.rsa.create(kdf, {rng: rnd});

      var rsaPublicKey = RSA.setPublicKey(new JSBN.BigInteger(n), new JSBN.BigInteger(e));
      var rsaPrivateKey = RSA.setPrivateKey(new JSBN.BigInteger(n),null , new JSBN.BigInteger(d));

      var result = kem.encrypt(rsaPublicKey, 128);
      ASSERT.equal(UTIL.bytesToHex(result.ciphertext), C0);
      ASSERT.equal(UTIL.bytesToHex(result.key), K);

      var decryptedKey = kem.decrypt(rsaPrivateKey, result.ciphertext, 128);
      ASSERT.equal(UTIL.bytesToHex(decryptedKey), K);

    });

    // C.6.3
    it('Test 3', function() {

      var n = '5888113332502691251761936431009284884966640757179802337490546478326238537107326596800820237597139824869184990638749556269785797065508097452399642780486933';
      var e = '65537';
      var d = '3202313555859948186315374524474173995679783580392140237044349728046479396037520308981353808895461806395564474639124525446044708705259675840210989546479265';

      var C0 = '4603e5324cab9cef8365c817052d954d44447b1667099edc69942d32cd594e4ffcf268ae3836e2c35744aaa53ae201fe499806b67dedaa26bf72ecbd117a6fc0';
      var K = '09e2decf2a6e1666c2f6071ff4298305e2643fd510a2403db42a8743cb989de86e668d168cbe604611ac179f819a3d18412e9eb45668f2923c087c12fee0c5a0d2a8aa70185401fbbd99379ec76c663e875a60b4aacb1319fa11c3365a8b79a44669f26fb555c80391847b05eca1cb5cf8c2d531448d33fbaca19f6410ee1fcb';

      var kdf = new KEM.kdf1(MD.sha256.create(), 20);

      var rnd = new FixedSecureRandom('032e45326fa859a72ec235acff929b15d1372e30b207255f0611b8f785d764374152e0ac009e509e7ba30cd2f1778e113b64e135cf4e2292c75efe5288edfda4');

      var kem = KEM.rsa.create(kdf, {rng: rnd});

      var rsaPublicKey = RSA.setPublicKey(new JSBN.BigInteger(n), new JSBN.BigInteger(e));
      var rsaPrivateKey = RSA.setPrivateKey(new JSBN.BigInteger(n),null , new JSBN.BigInteger(d));

      var result = kem.encrypt(rsaPublicKey, 128);
      ASSERT.equal(UTIL.bytesToHex(result.ciphertext), C0);
      ASSERT.equal(UTIL.bytesToHex(result.key), K);

      var decryptedKey = kem.decrypt(rsaPrivateKey, result.ciphertext, 128);
      ASSERT.equal(UTIL.bytesToHex(decryptedKey), K);

    });

    // C.6.4
    it('Test 4', function() {

      var n = '5888113332502691251761936431009284884966640757179802337490546478326238537107326596800820237597139824869184990638749556269785797065508097452399642780486933';
      var e = '65537';
      var d = '3202313555859948186315374524474173995679783580392140237044349728046479396037520308981353808895461806395564474639124525446044708705259675840210989546479265';

      var C0 = '4603e5324cab9cef8365c817052d954d44447b1667099edc69942d32cd594e4ffcf268ae3836e2c35744aaa53ae201fe499806b67dedaa26bf72ecbd117a6fc0';
      var K = '10a2403db42a8743cb989de86e668d168cbe604611ac179f819a3d18412e9eb45668f2923c087c12fee0c5a0d2a8aa70185401fbbd99379ec76c663e875a60b4aacb1319fa11c3365a8b79a44669f26fb555c80391847b05eca1cb5cf8c2d531448d33fbaca19f6410ee1fcb260892670e0814c348664f6a7248aaf998a3acc6';

      var kdf = new KEM.kdf2(MD.sha256.create(), 20);

      var rnd = new FixedSecureRandom('032e45326fa859a72ec235acff929b15d1372e30b207255f0611b8f785d764374152e0ac009e509e7ba30cd2f1778e113b64e135cf4e2292c75efe5288edfda4');

      var kem = KEM.rsa.create(kdf, {rng: rnd});

      var rsaPublicKey = RSA.setPublicKey(new JSBN.BigInteger(n), new JSBN.BigInteger(e));
      var rsaPrivateKey = RSA.setPrivateKey(new JSBN.BigInteger(n), null, new JSBN.BigInteger(d));

      var result = kem.encrypt(rsaPublicKey, 128);
      ASSERT.equal(UTIL.bytesToHex(result.ciphertext), C0);
      ASSERT.equal(UTIL.bytesToHex(result.key), K);

      var decryptedKey = kem.decrypt(rsaPrivateKey, result.ciphertext, 128);
      ASSERT.equal(UTIL.bytesToHex(decryptedKey), K);

    });
  });
}

// check for AMD
if(typeof define === 'function') {
  define([
    'forge/kem',
    'forge/md',
    'forge/rsa',
    'forge/util',
    'forge/jsbn',
    'forge/random'
  ], function(KEM, MD, RSA, UTIL, JSBN, RANDOM) {
    Tests(
      // Global provided by test harness
      ASSERT,
      KEM(),
      MD(),
      RSA(),
      UTIL(),
      JSBN(),
      RANDOM()
    );
  });
} else if(typeof module === 'object' && module.exports) {
  // assume NodeJS
  Tests(
    require('assert'),
    require('../../js/kem')(),
    require('../../js/md')(),
    require('../../js/rsa')(),
    require('../../js/util')(),
    require('../../js/jsbn')(),
    require('../../js/random')());
}

})();
