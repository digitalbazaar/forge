(function() {

function Tests(ASSERT, AES, UTIL) {
  describe('aes', function() {
    it('should encrypt a single block with a 128-bit key', function() {
      var key = [0x00010203, 0x04050607, 0x08090a0b, 0x0c0d0e0f];
      var block = [0x00112233, 0x44556677, 0x8899aabb, 0xccddeeff];

      var output = [];
      var w = AES._expandKey(key, false);
      AES._updateBlock(w, block, output, false);

      var out = UTIL.createBuffer();
      out.putInt32(output[0]);
      out.putInt32(output[1]);
      out.putInt32(output[2]);
      out.putInt32(output[3]);

      ASSERT.equal(out.toHex(), '69c4e0d86a7b0430d8cdb78070b4c55a');
    });

    it('should decrypt a single block with a 128-bit key', function() {
      var key = [0x00010203, 0x04050607, 0x08090a0b, 0x0c0d0e0f];
      var block = [0x69c4e0d8, 0x6a7b0430, 0xd8cdb780, 0x70b4c55a];

      var output = [];
      var w = AES._expandKey(key, true);
      AES._updateBlock(w, block, output, true);

      var out = UTIL.createBuffer();
      out.putInt32(output[0]);
      out.putInt32(output[1]);
      out.putInt32(output[2]);
      out.putInt32(output[3]);

      ASSERT.equal(out.toHex(), '00112233445566778899aabbccddeeff');
    });

    it('should encrypt a single block with a 192-bit key', function() {
        var key = [
          0x00010203, 0x04050607, 0x08090a0b, 0x0c0d0e0f,
          0x10111213, 0x14151617];
        var block = [0x00112233, 0x44556677, 0x8899aabb, 0xccddeeff];

        var output = [];
        var w = AES._expandKey(key, false);
        AES._updateBlock(w, block, output, false);

        var out = UTIL.createBuffer();
        out.putInt32(output[0]);
        out.putInt32(output[1]);
        out.putInt32(output[2]);
        out.putInt32(output[3]);

        ASSERT.equal(out.toHex(), 'dda97ca4864cdfe06eaf70a0ec0d7191');
    });

    it('should decrypt a single block with a 192-bit key', function() {
        var key = [
          0x00010203, 0x04050607, 0x08090a0b, 0x0c0d0e0f,
          0x10111213, 0x14151617];
        var block = [0xdda97ca4, 0x864cdfe0, 0x6eaf70a0, 0xec0d7191];

        var output = [];
        var w = AES._expandKey(key, true);
        AES._updateBlock(w, block, output, true);

        var out = UTIL.createBuffer();
        out.putInt32(output[0]);
        out.putInt32(output[1]);
        out.putInt32(output[2]);
        out.putInt32(output[3]);

        ASSERT.equal(out.toHex(), '00112233445566778899aabbccddeeff');
    });

    it('should encrypt a single block with a 256-bit key', function() {
        var key = [
          0x00010203, 0x04050607, 0x08090a0b, 0x0c0d0e0f,
          0x10111213, 0x14151617, 0x18191a1b, 0x1c1d1e1f];
        var block = [0x00112233, 0x44556677, 0x8899aabb, 0xccddeeff];

        var output = [];
        var w = AES._expandKey(key, false);
        AES._updateBlock(w, block, output, false);

        var out = UTIL.createBuffer();
        out.putInt32(output[0]);
        out.putInt32(output[1]);
        out.putInt32(output[2]);
        out.putInt32(output[3]);

        ASSERT.equal(out.toHex(), '8ea2b7ca516745bfeafc49904b496089');
    });

    it('should decrypt a single block with a 256-bit key', function() {
        var key = [
          0x00010203, 0x04050607, 0x08090a0b, 0x0c0d0e0f,
          0x10111213, 0x14151617, 0x18191a1b, 0x1c1d1e1f];
        var block = [0x8ea2b7ca, 0x516745bf, 0xeafc4990, 0x4b496089];

        var output = [];
        var w = AES._expandKey(key, true);
        AES._updateBlock(w, block, output, true);

        var out = UTIL.createBuffer();
        out.putInt32(output[0]);
        out.putInt32(output[1]);
        out.putInt32(output[2]);
        out.putInt32(output[3]);

        ASSERT.equal(out.toHex(), '00112233445566778899aabbccddeeff');
    });

    // AES-128-CBC
    (function() {
      var keys = [
        '06a9214036b8a15b512e03d534120006',
        'c286696d887c9aa0611bbb3e2025a45a',
        '6c3ea0477630ce21a2ce334aa746c2cd',
        '56e47a38c5598974bc46903dba290349'
      ];

      var ivs = [
        '3dafba429d9eb430b422da802c9fac41',
        '562e17996d093d28ddb3ba695a2e6f58',
        'c782dc4c098c66cbd9cd27d825682c81',
        '8ce82eefbea0da3c44699ed7db51b7d9'
      ];

      var inputs = [
        'Single block msg',
        '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f',
        'This is a 48-byte message (exactly 3 AES blocks)',
        'a0a1a2a3a4a5a6a7a8a9aaabacadaeaf' +
          'b0b1b2b3b4b5b6b7b8b9babbbcbdbebf' +
          'c0c1c2c3c4c5c6c7c8c9cacbcccdcecf' +
          'd0d1d2d3d4d5d6d7d8d9dadbdcdddedf'
      ];

      var outputs = [
        'e353779c1079aeb82708942dbe77181a',
        'd296cd94c2cccf8a3a863028b5e1dc0a7586602d253cfff91b8266bea6d61ab1',
        'd0a02b3836451753d493665d33f0e886' +
          '2dea54cdb293abc7506939276772f8d5' +
          '021c19216bad525c8579695d83ba2684',
        'c30e32ffedc0774e6aff6af0869f71aa' +
          '0f3af07a9a31a9c684db207eb0ef8e4e' +
          '35907aa632c3ffdf868bb7b29d3d46ad' +
          '83ce9f9a102ee99d49a53e87f4c3da55'
      ];

      for(var i = 0; i < keys.length; ++i) {
        (function(i) {
          var key = UTIL.hexToBytes(keys[i]);
          var iv = UTIL.hexToBytes(ivs[i]);
          var input = (i & 1) ? UTIL.hexToBytes(inputs[i]) : inputs[i];
          var output = UTIL.hexToBytes(outputs[i]);

          it('should aes-128-cbc encrypt: ' + inputs[i], function() {
            // encrypt w/no padding
            var cipher = AES.createEncryptionCipher(key, 'CBC');
            cipher.start(iv);
            cipher.update(UTIL.createBuffer(input));
            cipher.finish(function(){return true;});
            ASSERT.equal(cipher.output.toHex(), outputs[i]);
          });

          it('should aes-128-cbc decrypt: ' + outputs[i], function() {
            // decrypt w/no padding
            var cipher = AES.createDecryptionCipher(key, 'CBC');
            cipher.start(iv);
            cipher.update(UTIL.createBuffer(output));
            cipher.finish(function(){return true;});
            var out = (i & 1) ? cipher.output.toHex() : cipher.output.bytes();
            ASSERT.equal(out, inputs[i]);
          });
        })(i);
      }
    })();

    // AES-128-CFB
    (function() {
      var keys = [
        '00000000000000000000000000000000',
        '2b7e151628aed2a6abf7158809cf4f3c',
        '2b7e151628aed2a6abf7158809cf4f3c',
        '2b7e151628aed2a6abf7158809cf4f3c',
        '2b7e151628aed2a6abf7158809cf4f3c',
        '00000000000000000000000000000000'
      ];

      var ivs = [
        '80000000000000000000000000000000',
        '000102030405060708090a0b0c0d0e0f',
        '3B3FD92EB72DAD20333449F8E83CFB4A',
        'C8A64537A0B3A93FCDE3CDAD9F1CE58B',
        '26751F67A3CBB140B1808CF187A4F4DF',
        '60f9ff04fac1a25657bf5b36b5efaf75'
      ];

      var inputs = [
        '00000000000000000000000000000000',
        '6bc1bee22e409f96e93d7e117393172a',
        'ae2d8a571e03ac9c9eb76fac45af8e51',
        '30c81c46a35ce411e5fbc1191a0a52ef',
        'f69f2445df4f9b17ad2b417be66c3710',
        'This is a 48-byte message (exactly 3 AES blocks)'
      ];

      var outputs = [
        '3ad78e726c1ec02b7ebfe92b23d9ec34',
        '3b3fd92eb72dad20333449f8e83cfb4a',
        'c8a64537a0b3a93fcde3cdad9f1ce58b',
        '26751f67a3cbb140b1808cf187a4f4df',
        'c04b05357c5d1c0eeac4c66f9ff7f2e6',
        '52396a2ba1ba420c5e5b699a814944d8' +
          'f4e7fbf984a038319fbc0b4ee45cfa6f' +
          '07b2564beab5b5e92dbd44cb345f49b4'
      ];

      for(var i = 0; i < keys.length; ++i) {
        (function(i) {
          var key = UTIL.hexToBytes(keys[i]);
          var iv = UTIL.hexToBytes(ivs[i]);
          var input = (i !== 5) ? UTIL.hexToBytes(inputs[i]) : inputs[i];
          var output = UTIL.hexToBytes(outputs[i]);

          it('should aes-128-cfb encrypt: ' + inputs[i], function() {
            // encrypt w/no padding
            var cipher = AES.createEncryptionCipher(key, 'CFB');
            cipher.start(iv);
            cipher.update(UTIL.createBuffer(input));
            cipher.finish();
            ASSERT.equal(cipher.output.toHex(), outputs[i]);
          });

          it('should aes-128-cfb decrypt: ' + outputs[i], function() {
            // decrypt w/no padding
            var cipher = AES.createDecryptionCipher(key, 'CFB');
            cipher.start(iv);
            cipher.update(UTIL.createBuffer(output));
            cipher.finish();
            var out = (i !== 5) ?
              cipher.output.toHex() : cipher.output.getBytes();
            ASSERT.equal(out, inputs[i]);
          });
        })(i);
      }
    })();

    // AES-128-OFB
    (function() {
      var keys = [
        '00000000000000000000000000000000',
        '00000000000000000000000000000000'
      ];

      var ivs = [
        '80000000000000000000000000000000',
        'c8ca0d6a35dbeac776e911ee16bea7d3'
      ];

      var inputs = [
        '00000000000000000000000000000000',
        'This is a 48-byte message (exactly 3 AES blocks)'
      ];

      var outputs = [
        '3ad78e726c1ec02b7ebfe92b23d9ec34',
        '39c0190727a76b2a90963426f63689cf' +
          'cdb8a2be8e20c5e877a81a724e3611f6' +
          '2ecc386f2e941b2441c838906002be19'
      ];

      for(var i = 0; i < keys.length; ++i) {
        (function(i) {
          var key = UTIL.hexToBytes(keys[i]);
          var iv = UTIL.hexToBytes(ivs[i]);
          var input = (i !== 1) ? UTIL.hexToBytes(inputs[i]) : inputs[i];
          var output = UTIL.hexToBytes(outputs[i]);

          it('should aes-128-ofb encrypt: ' + inputs[i], function() {
            // encrypt w/no padding
            var cipher = AES.createEncryptionCipher(key, 'OFB');
            cipher.start(iv);
            cipher.update(UTIL.createBuffer(input));
            cipher.finish();
            ASSERT.equal(cipher.output.toHex(), outputs[i]);
          });

          it('should aes-128-ofb decrypt: ' + outputs[i], function() {
            // decrypt w/no padding
            var cipher = AES.createDecryptionCipher(key, 'OFB');
            cipher.start(iv);
            cipher.update(UTIL.createBuffer(output));
            cipher.finish();
            var out = (i !== 1) ?
              cipher.output.toHex() : cipher.output.getBytes();
            ASSERT.equal(out, inputs[i]);
          });
        })(i);
      }
    })();

    // AES-128-CTR
    (function() {
      var keys = [
        '2b7e151628aed2a6abf7158809cf4f3c',
        '00000000000000000000000000000000',
      ];

      var ivs = [
        'f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff',
        '650cdb80ff9fc758342d2bd99ee2abcf',
      ];

      var inputs = [
        '6bc1bee22e409f96e93d7e117393172a',
        'This is a 48-byte message (exactly 3 AES blocks)',
      ];

      var outputs = [
        '874d6191b620e3261bef6864990db6ce',
        '5ede11d00e9a76ec1d5e7e811ea3dd1c' +
          'e09ee941210f825d35718d3282796f1c' +
          '07c3f1cb424f2b365766ab5229f5b5a4'
      ];

      for(var i = 0; i < keys.length; ++i) {
        (function(i) {
          var key = UTIL.hexToBytes(keys[i]);
          var iv = UTIL.hexToBytes(ivs[i]);
          var input = (i !== 1) ? UTIL.hexToBytes(inputs[i]) : inputs[i];
          var output = UTIL.hexToBytes(outputs[i]);

          it('should aes-128-ctr encrypt: ' + inputs[i], function() {
            // encrypt w/no padding
            var cipher = AES.createEncryptionCipher(key, 'CTR');
            cipher.start(iv);
            cipher.update(UTIL.createBuffer(input));
            cipher.finish();
            ASSERT.equal(cipher.output.toHex(), outputs[i]);
          });

          it('should aes-128-ctr decrypt: ' + outputs[i], function() {
            // decrypt w/no padding
            var cipher = AES.createDecryptionCipher(key, 'CTR');
            cipher.start(iv);
            cipher.update(UTIL.createBuffer(output));
            cipher.finish();
            var out = (i !== 1) ?
              cipher.output.toHex() : cipher.output.getBytes();
            ASSERT.equal(out, inputs[i]);
          });
        })(i);
      }
    })();

    // AES-256-CFB
    (function() {
      var keys = [
        '861009ec4d599fab1f40abc76e6f89880cff5833c79c548c99f9045f191cd90b'
      ];

      var ivs = [
        'd927ad81199aa7dcadfdb4e47b6dc694'
      ];

      var inputs = [
        'MY-DATA-AND-HERE-IS-MORE-DATA'
      ];

      var outputs = [
        '80eb666a9fc9e263faf71e87ffc94451d7d8df7cfcf2606470351dd5ac'
      ];

      for(var i = 0; i < keys.length; ++i) {
        (function(i) {
          var key = UTIL.hexToBytes(keys[i]);
          var iv = UTIL.hexToBytes(ivs[i]);
          var input = inputs[i];
          var output = UTIL.hexToBytes(outputs[i]);

          it('should aes-256-cfb encrypt: ' + inputs[i], function() {
            // encrypt w/no padding
            var cipher = AES.createEncryptionCipher(key, 'CFB');
            cipher.start(iv);
            cipher.update(UTIL.createBuffer(input));
            cipher.finish();
            ASSERT.equal(cipher.output.toHex(), outputs[i]);
          });

          it('should aes-256-cfb decrypt: ' + outputs[i], function() {
            // decrypt w/no padding
            var cipher = AES.createDecryptionCipher(key, 'CFB');
            cipher.start(iv);
            cipher.update(UTIL.createBuffer(output));
            cipher.finish();
            var out = cipher.output.getBytes();
            ASSERT.equal(out, inputs[i]);
          });
        })(i);
      }
    })();
  });
}

// check for AMD
if(typeof define === 'function') {
  define([
    'forge/aes',
    'forge/util'
  ], function(AES, UTIL) {
    Tests(
      // Global provided by test harness
      ASSERT,
      AES(),
      UTIL()
    );
  });
}
// assume NodeJS
else if(typeof module === 'object' && module.exports) {
  Tests(
    require('assert'),
    require('../../js/aes')(),
    require('../../js/util')());
}

})();
