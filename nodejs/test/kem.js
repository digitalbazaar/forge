(function() {

function Tests(ASSERT, KEM, MD, MGF, RSA, UTIL, JSBN) {

  function initArray(length) {
    var array = [];
    for ( var i = 0; i<length; i++ ) {
      array.push(0);
    }
    return array;
  }

  function arraycopy(src, srcPos, dest, destPos, length) {
    for ( var i = 0; i<destPos; i++ ) {
      dest[i] =0;
    }
    for ( var i = 0; i<length; i++ ) {
      dest[destPos + i] = src[srcPos+i];
    }
  }

  function FixedSecureRandom(str) {
    var _str = str;
    var bytes = strToBytes(str);
    var index = 0;
    
    // for ( var i = 0; i < str.length; ++i ) {
    //   bytes.push(str.charCodeAt(i));
    // }

    this.getBytes = this.getBytesSync = function(count, callback) {
      // var r = _str.substr(index,count);
      // console.log('count', count);

      var out = initArray(count);
      arraycopy(bytes, index, out, 0, out.length);
        
      index += count;

      // var result = "";
      // for (var i = 0; i < out.length; i++) {
      //   result += String.fromCharCode(parseInt(out[i],8));
      // }
      // return result;
      var result = "";
      for (var i = 0; i < out.length; i++) {
        result += out[i].toString();
      }
      return result;
      // return r;
    }


  }

  function hex2a(hex) {
    var str = '';
    for (var i = 0; i < hex.length; i += 2) {
      var n =parseInt(hex.substr(i, 2), 16);
      
      if ( n > 127 ) n = n - 256;
      console.log("n",n)
      str += String.fromCharCode(n);
    }
     
    return str;
  } 

  function strToBytes (str) {
    str = hex2a(str);

    var bytes = [];
    for ( var i=0; i<str.length; i++ ) {
      bytes.push(str.charCodeAt(i));
    }
    return bytes;
  }




  describe('kem', function() {
    it('should escrypt and decrypt', function() {
      
      var mgf = MGF.mgf1.create(MD.sha256.create());
      var kem = KEM.create(mgf);
      // console.log(kem);

      var pair = RSA.generateKeyPair(512);
      
      var out = initArray(64);
      var key1 = kem.encrypt(pair.publicKey, out, 0, 256);

      console.log("key1", key1);

      var key2 = kem.decrypt(pair.privateKey, out, 0, out.length, 256);

      console.log("key2", key2);

      ASSERT.deepEqual(key1, key2);

    });
  });

  describe('RsaKeyEncapsulationTestVectors', function() {
    it("Test 1", function() {

      var n = "5888113332502691251761936431009284884966640757179802337490546478326238537107326596800820237597139824869184990638749556269785797065508097452399642780486933";
      var e = "65537";
      var d = "3202313555859948186315374524474173995679783580392140237044349728046479396037520308981353808895461806395564474639124525446044708705259675840210989546479265";

      var C0 = "4603e5324cab9cef8365c817052d954d44447b1667099edc69942d32cd594e4ffcf268ae3836e2c35744aaa53ae201fe499806b67dedaa26bf72ecbd117a6fc0";
      var K = "10a2403db42a8743cb989de86e668d168cbe604611ac179f819a3d18412e9eb45668f2923c087c12fee0c5a0d2a8aa70185401fbbd99379ec76c663e875a60b4aacb1319fa11c3365a8b79a44669f26fb555c80391847b05eca1cb5cf8c2d531448d33fbaca19f6410ee1fcb260892670e0814c348664f6a7248aaf998a3acc6";

      var mgf = MGF.mgf1.create(MD.sha1.create());
      
      
      var rnd = new FixedSecureRandom("032e45326fa859a72ec235acff929b15d1372e30b207255f0611b8f785d764374152e0ac009e509e7ba30cd2f1778e113b64e135cf4e2292c75efe5288edfda4");

      var kem = KEM.create(mgf, rnd);

      // console.log(kem);

      // var pair = RSA.generateKeyPair(512);
      var rsaPublicKey = RSA.setPublicKey(new JSBN.BigInteger(n), new JSBN.BigInteger(e));
      var rsaPrivateKey = RSA.setPrivateKey(new JSBN.BigInteger(n),null , new JSBN.BigInteger(d));
      console.log("rsaPrivateKey", rsaPrivateKey.n.bitLength());
      
      var expectedC0 = strToBytes(C0);
      var expectedK = strToBytes(K);

      var out = initArray(64);
      var generatedKey = kem.encrypt(rsaPublicKey, out, 0, 128);
      // console.log('expectedK', expectedK);
      // console.log('generatedKey',generatedKey);
      // ASSERT.deepEqual(expectedK,generatedKey);
      console.log('expectedC0', expectedC0)
      console.log('out',out);
      ASSERT.deepEqual(expectedC0,out);



      // Assert.assertArrayEquals(_expectedC0, out);
      // Assert.assertArrayEquals(_expectedK, generatedKey);

      // byte[] decryptedKey =
      //     _rsaKeyEncapsulation.decrypt(_rsaPrivateKey, out, _keyLength);
      // Assert.assertArrayEquals(_expectedK, decryptedKey);




    });
  });
}

// check for AMD
if(typeof define === 'function') {
  define([
    'forge/kem',
    'forge/md',
    'forge/mgf',
    'forge/rsa',
    'forge/util',
    'forge/jsbn'
  ], function(KEM, MD, MGF, RSA, UTIL, JSBN) {
    Tests(
      // Global provided by test harness
      ASSERT,
      KEM(),
      MD(),
      MGF(),
      RSA(),
      UTIL(),
      JSBN()
    );
  });
} else if(typeof module === 'object' && module.exports) {
  // assume NodeJS
  Tests(
    require('assert'),
    require('../../js/kem')(),
    require('../../js/md')(),
    require('../../js/mgf')(),
    require('../../js/rsa')(),
    require('../../js/util')(),
    require('../../js/jsbn')());
}

})();
