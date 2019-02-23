var ASSERT = require('assert');
var UTIL = require('../../lib/util');

(function() {
  // custom assertion to test array-like objects
  function assertArrayEqual(actual, expected) {
    ASSERT.equal(actual.length, expected.length);
    for(var idx = 0; idx < expected.length; idx++) {
      ASSERT.equal(actual[idx], expected[idx]);
    }
  }

  describe('util', function() {
    it('should put bytes into a buffer', function() {
      var b = UTIL.createBuffer();
      b.putByte(1);
      b.putByte(2);
      b.putByte(3);
      b.putByte(4);
      b.putInt32(4);
      b.putByte(1);
      b.putByte(2);
      b.putByte(3);
      b.putInt32(4294967295);
      var hex = b.toHex();
      ASSERT.equal(hex, '0102030400000004010203ffffffff');

      var bytes = [];
      while(b.length() > 0) {
        bytes.push(b.getByte());
      }
      ASSERT.deepEqual(
        bytes, [1, 2, 3, 4, 0, 0, 0, 4, 1, 2, 3, 255, 255, 255, 255]);
    });

    it('should put bytes from an Uint8Array into a buffer', function() {
      if(typeof Uint8Array === 'undefined') {
        return;
      }
      var data = [1, 2, 3, 4, 0, 0, 0, 4, 1, 2, 3, 255, 255, 255, 255];
      var ab = new Uint8Array(data);
      var b = UTIL.createBuffer(ab);
      var hex = b.toHex();
      ASSERT.equal(hex, '0102030400000004010203ffffffff');

      var bytes = [];
      while(b.length() > 0) {
        bytes.push(b.getByte());
      }
      ASSERT.deepEqual(bytes, data);
    });

    it('should convert bytes from hex', function() {
      var hex = '0102030400000004010203ffffffff';
      var b = UTIL.createBuffer();
      b.putBytes(UTIL.hexToBytes(hex));
      ASSERT.equal(b.toHex(), hex);
    });

    it('should put 0 into a buffer using two\'s complement', function() {
      var b = UTIL.createBuffer();
      b.putSignedInt(0, 8);
      ASSERT.equal(b.toHex(), '00');
    });

    it('should put 0 into a buffer using two\'s complement w/2 bytes', function() {
      var b = UTIL.createBuffer();
      b.putSignedInt(0, 16);
      ASSERT.equal(b.toHex(), '0000');
    });

    it('should put 127 into a buffer using two\'s complement', function() {
      var b = UTIL.createBuffer();
      b.putSignedInt(127, 8);
      ASSERT.equal(b.toHex(), '7f');
    });

    it('should put 127 into a buffer using two\'s complement w/2 bytes', function() {
      var b = UTIL.createBuffer();
      b.putSignedInt(127, 16);
      ASSERT.equal(b.toHex(), '007f');
    });

    it('should put 128 into a buffer using two\'s complement', function() {
      var b = UTIL.createBuffer();
      b.putSignedInt(128, 16);
      ASSERT.equal(b.toHex(), '0080');
    });

    it('should put 256 into a buffer using two\'s complement', function() {
      var b = UTIL.createBuffer();
      b.putSignedInt(256, 16);
      ASSERT.equal(b.toHex(), '0100');
    });

    it('should put -128 into a buffer using two\'s complement', function() {
      var b = UTIL.createBuffer();
      b.putSignedInt(-128, 8);
      ASSERT.equal(b.toHex(), '80');
    });

    it('should put -129 into a buffer using two\'s complement', function() {
      var b = UTIL.createBuffer();
      b.putSignedInt(-129, 16);
      ASSERT.equal(b.toHex(), 'ff7f');
    });

    it('should get 0 from a buffer using two\'s complement', function() {
      var x = 0;
      var n = 8;
      var b = UTIL.createBuffer();
      b.putSignedInt(x, n);
      ASSERT.equal(b.getSignedInt(n), x);
    });

    it('should get 127 from a buffer using two\'s complement', function() {
      var x = 127;
      var n = 8;
      var b = UTIL.createBuffer();
      b.putSignedInt(x, n);
      ASSERT.equal(b.getSignedInt(n), x);
    });

    it('should get 128 from a buffer using two\'s complement', function() {
      var x = 128;
      var n = 16;
      var b = UTIL.createBuffer();
      b.putSignedInt(x, n);
      ASSERT.equal(b.getSignedInt(n), x);
    });

    it('should get 256 from a buffer using two\'s complement', function() {
      var x = 256;
      var n = 16;
      var b = UTIL.createBuffer();
      b.putSignedInt(x, n);
      ASSERT.equal(b.getSignedInt(n), x);
    });

    it('should get -128 from a buffer using two\'s complement', function() {
      var x = -128;
      var n = 8;
      var b = UTIL.createBuffer();
      b.putSignedInt(x, n);
      ASSERT.equal(b.getSignedInt(n), x);
    });

    it('should get -129 from a buffer using two\'s complement', function() {
      var x = -129;
      var n = 16;
      var b = UTIL.createBuffer();
      b.putSignedInt(x, n);
      ASSERT.equal(b.getSignedInt(n), x);
    });

    it('should getInt(8) from buffer', function() {
      var b = UTIL.createBuffer(UTIL.hexToBytes('12'));
      ASSERT.equal(b.getInt(8), 0x12);
      ASSERT.equal(b.length(), 0);
    });

    it('should getInt(8)x2 from buffer', function() {
      var b = UTIL.createBuffer(UTIL.hexToBytes('1221'));
      ASSERT.equal(b.getInt(8), 0x12);
      ASSERT.equal(b.getInt(8), 0x21);
      ASSERT.equal(b.length(), 0);
    });

    it('should getInt(16) from buffer', function() {
      var b = UTIL.createBuffer(UTIL.hexToBytes('1234'));
      ASSERT.equal(b.getInt(16), 0x1234);
      ASSERT.equal(b.length(), 0);
    });

    it('should getInt(16)x2 from buffer', function() {
      var b = UTIL.createBuffer(UTIL.hexToBytes('12344321'));
      ASSERT.equal(b.getInt(16), 0x1234);
      ASSERT.equal(b.getInt(16), 0x4321);
      ASSERT.equal(b.length(), 0);
    });

    it('should getInt(24) from buffer', function() {
      var b = UTIL.createBuffer(UTIL.hexToBytes('123456'));
      ASSERT.equal(b.getInt(24), 0x123456);
      ASSERT.equal(b.length(), 0);
    });

    it('should getInt(24)x2 from buffer', function() {
      var b = UTIL.createBuffer(UTIL.hexToBytes('123456654321'));
      ASSERT.equal(b.getInt(24), 0x123456);
      ASSERT.equal(b.getInt(24), 0x654321);
      ASSERT.equal(b.length(), 0);
    });

    it('should getInt(32) from buffer', function() {
      var b = UTIL.createBuffer(UTIL.hexToBytes('12345678'));
      ASSERT.equal(b.getInt(32), 0x12345678);
      ASSERT.equal(b.length(), 0);
    });

    it('should getInt(32)x2 from buffer', function() {
      var b = UTIL.createBuffer(UTIL.hexToBytes('1234567887654321'));
      ASSERT.equal(b.getInt(32), 0x12345678);
      // FIXME: getInt bit shifts create signed int
      ASSERT.equal(b.getInt(32), 0x87654321 << 0);
      ASSERT.equal(b.length(), 0);
    });

    it('should throw for getInt(1) from buffer', function() {
      var b = UTIL.createBuffer();
      ASSERT.throws(function() {
        b.getInt(1);
      });
    });

    it('should throw for getInt(33) from buffer', function() {
      var b = UTIL.createBuffer();
      ASSERT.throws(function() {
        b.getInt(33);
      });
    });

    // TODO: add get/put tests at limits of signed/unsigned types

    it('should base64 encode some bytes', function() {
      var s1 = '00010203050607080A0B0C0D0F1011121415161719';
      var s2 = 'MDAwMTAyMDMwNTA2MDcwODBBMEIwQzBEMEYxMDExMTIxNDE1MTYxNzE5';
      ASSERT.equal(UTIL.encode64(s1), s2);
    });

    it('should base64 decode some bytes', function() {
      var s1 = '00010203050607080A0B0C0D0F1011121415161719';
      var s2 = 'MDAwMTAyMDMwNTA2MDcwODBBMEIwQzBEMEYxMDExMTIxNDE1MTYxNzE5';
      ASSERT.equal(UTIL.decode64(s2), s1);
    });

    it('should base64 encode some bytes using util.binary.base64', function() {
      var s1 = new Uint8Array([
        0x30, 0x30, 0x30, 0x31, 0x30, 0x32, 0x30, 0x33, 0x30,
        0x35, 0x30, 0x36, 0x30, 0x37, 0x30, 0x38, 0x30, 0x41,
        0x30, 0x42, 0x30, 0x43, 0x30, 0x44, 0x30, 0x46, 0x31,
        0x30, 0x31, 0x31, 0x31, 0x32, 0x31, 0x34, 0x31, 0x35,
        0x31, 0x36, 0x31, 0x37, 0x31, 0x39]);
      var s2 = 'MDAwMTAyMDMwNTA2MDcwODBBMEIwQzBEMEYxMDExMTIxNDE1MTYxNzE5';
      ASSERT.equal(UTIL.binary.base64.encode(s1), s2);
    });

    it('should base64 encode some odd-length bytes using util.binary.base64', function() {
      var s1 = new Uint8Array([
        0x30, 0x30, 0x30, 0x31, 0x30, 0x32, 0x30, 0x33, 0x30,
        0x35, 0x30, 0x36, 0x30, 0x37, 0x30, 0x38, 0x30, 0x41,
        0x30, 0x42, 0x30, 0x43, 0x30, 0x44, 0x30, 0x46, 0x31,
        0x30, 0x31, 0x31, 0x31, 0x32, 0x31, 0x34, 0x31, 0x35,
        0x31, 0x36, 0x31, 0x37, 0x31, 0x39, 0x31, 0x41, 0x31,
        0x42]);
      var s2 = 'MDAwMTAyMDMwNTA2MDcwODBBMEIwQzBEMEYxMDExMTIxNDE1MTYxNzE5MUExQg==';
      ASSERT.equal(UTIL.binary.base64.encode(s1), s2);
    });

    it('should base64 decode some bytes using util.binary.base64', function() {
      var s1 = new Uint8Array([
        0x30, 0x30, 0x30, 0x31, 0x30, 0x32, 0x30, 0x33, 0x30,
        0x35, 0x30, 0x36, 0x30, 0x37, 0x30, 0x38, 0x30, 0x41,
        0x30, 0x42, 0x30, 0x43, 0x30, 0x44, 0x30, 0x46, 0x31,
        0x30, 0x31, 0x31, 0x31, 0x32, 0x31, 0x34, 0x31, 0x35,
        0x31, 0x36, 0x31, 0x37, 0x31, 0x39]);
      var s2 = 'MDAwMTAyMDMwNTA2MDcwODBBMEIwQzBEMEYxMDExMTIxNDE1MTYxNzE5';
      ASSERT.deepEqual(UTIL.binary.base64.decode(s2), s1);
    });

    it('should base64 decode some odd-length bytes using util.binary.base64', function() {
      var s1 = new Uint8Array([
        0x30, 0x30, 0x30, 0x31, 0x30, 0x32, 0x30, 0x33, 0x30,
        0x35, 0x30, 0x36, 0x30, 0x37, 0x30, 0x38, 0x30, 0x41,
        0x30, 0x42, 0x30, 0x43, 0x30, 0x44, 0x30, 0x46, 0x31,
        0x30, 0x31, 0x31, 0x31, 0x32, 0x31, 0x34, 0x31, 0x35,
        0x31, 0x36, 0x31, 0x37, 0x31, 0x39, 0x31, 0x41, 0x31,
        0x42]);
      var s2 = 'MDAwMTAyMDMwNTA2MDcwODBBMEIwQzBEMEYxMDExMTIxNDE1MTYxNzE5MUExQg==';
      assertArrayEqual(UTIL.binary.base64.decode(s2), s1);
    });

    it('should base58 encode some bytes', function() {
      if(typeof Uint8Array === 'undefined') {
        return;
      }
      var buffer = new Uint8Array([
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07]);
      var encoded = UTIL.binary.base58.encode(buffer);
      ASSERT.equal(encoded, '13DUyZY2dc');
    });

    it('should base58 encode some bytes from a ByteBuffer', function() {
      if(typeof Uint8Array === 'undefined') {
        return;
      }
      var buffer = UTIL.createBuffer(new Uint8Array([
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07]));
      var encoded = UTIL.binary.base58.encode(buffer);
      ASSERT.equal(encoded, '13DUyZY2dc');
    });

    it('should base58 decode some bytes', function() {
      if(typeof Uint8Array === 'undefined') {
        return;
      }
      var decoded = UTIL.binary.base58.decode('13DUyZY2dc');
      var buffer = new Uint8Array([
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07]);
      ASSERT.equal(
        UTIL.createBuffer(decoded).toHex(),
        UTIL.createBuffer(buffer).toHex());
    });

    it('should base58 encode some bytes with whitespace', function() {
      if(typeof Uint8Array === 'undefined') {
        return;
      }
      var buffer = new Uint8Array([
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07]);
      var encoded = UTIL.binary.base58.encode(buffer, 4);
      ASSERT.equal(encoded, '13DU\r\nyZY2\r\ndc');
    });

    it('should base58 decode some bytes with whitespace', function() {
      if(typeof Uint8Array === 'undefined') {
        return;
      }
      var decoded = UTIL.binary.base58.decode('13DU\r\nyZY2\r\ndc');
      var buffer = new Uint8Array([
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07]);
      ASSERT.equal(
        UTIL.createBuffer(decoded).toHex(),
        UTIL.createBuffer(buffer).toHex());
    });

    it('should convert IPv4 0.0.0.0 textual address to 4-byte address', function() {
      var bytes = UTIL.bytesFromIP('0.0.0.0');
      var b = UTIL.createBuffer().fillWithByte(0, 4);
      ASSERT.equal(bytes, b.getBytes());
    });

    it('should convert IPv4 127.0.0.1 textual address to 4-byte address', function() {
      var bytes = UTIL.bytesFromIP('127.0.0.1');
      var b = UTIL.createBuffer();
      b.putByte(127);
      b.putByte(0);
      b.putByte(0);
      b.putByte(1);
      ASSERT.equal(bytes, b.getBytes());
    });

    it('should convert IPv6 :: textual address to 16-byte address', function() {
      var bytes = UTIL.bytesFromIP('::');
      var b = UTIL.createBuffer().fillWithByte(0, 16);
      ASSERT.equal(bytes, b.getBytes());
    });

    it('should convert IPv6 ::0 textual address to 16-byte address', function() {
      var bytes = UTIL.bytesFromIP('::0');
      var b = UTIL.createBuffer().fillWithByte(0, 16);
      ASSERT.equal(bytes, b.getBytes());
    });

    it('should convert IPv6 0:: textual address to 16-byte address', function() {
      var bytes = UTIL.bytesFromIP('0::');
      var b = UTIL.createBuffer().fillWithByte(0, 16);
      ASSERT.equal(bytes, b.getBytes());
    });

    it('should convert IPv6 ::1 textual address to 16-byte address', function() {
      var bytes = UTIL.bytesFromIP('::1');
      var b = UTIL.createBuffer().fillWithByte(0, 14);
      b.putBytes(UTIL.hexToBytes('0001'));
      ASSERT.equal(bytes, b.getBytes());
    });

    it('should convert IPv6 1:: textual address to 16-byte address', function() {
      var bytes = UTIL.bytesFromIP('1::');
      var b = UTIL.createBuffer();
      b.putBytes(UTIL.hexToBytes('0001'));
      b.fillWithByte(0, 14);
      ASSERT.equal(bytes, b.getBytes());
    });

    it('should convert IPv6 1::1 textual address to 16-byte address', function() {
      var bytes = UTIL.bytesFromIP('1::1');
      var b = UTIL.createBuffer();
      b.putBytes(UTIL.hexToBytes('0001'));
      b.fillWithByte(0, 12);
      b.putBytes(UTIL.hexToBytes('0001'));
      ASSERT.equal(bytes, b.getBytes());
    });

    it('should convert IPv6 1::1:0 textual address to 16-byte address', function() {
      var bytes = UTIL.bytesFromIP('1::1:0');
      var b = UTIL.createBuffer();
      b.putBytes(UTIL.hexToBytes('0001'));
      b.fillWithByte(0, 10);
      b.putBytes(UTIL.hexToBytes('0001'));
      b.putBytes(UTIL.hexToBytes('0000'));
      ASSERT.equal(bytes, b.getBytes());
    });

    it('should convert IPv6 2001:db8:0:1:1:1:1:1 textual address to 16-byte address', function() {
      var bytes = UTIL.bytesFromIP('2001:db8:0:1:1:1:1:1');
      var b = UTIL.createBuffer();
      b.putBytes(UTIL.hexToBytes('2001'));
      b.putBytes(UTIL.hexToBytes('0db8'));
      b.putBytes(UTIL.hexToBytes('0000'));
      b.putBytes(UTIL.hexToBytes('0001'));
      b.putBytes(UTIL.hexToBytes('0001'));
      b.putBytes(UTIL.hexToBytes('0001'));
      b.putBytes(UTIL.hexToBytes('0001'));
      b.putBytes(UTIL.hexToBytes('0001'));
      ASSERT.equal(bytes, b.getBytes());
    });

    it('should convert IPv4 0.0.0.0 byte address to textual representation', function() {
      var addr = '0.0.0.0';
      var bytes = UTIL.createBuffer().fillWithByte(0, 4).getBytes();
      var addr = UTIL.bytesToIP(bytes);
      ASSERT.equal(addr, '0.0.0.0');
    });

    it('should convert IPv4 0.0.0.0 byte address to textual representation', function() {
      var addr = '127.0.0.1';
      var bytes = UTIL.bytesFromIP(addr);
      var addr = UTIL.bytesToIP(bytes);
      ASSERT.equal(addr, '127.0.0.1');
    });

    it('should convert IPv6 :: byte address to canonical textual representation (RFC 5952)', function() {
      var addr = '::';
      var bytes = UTIL.createBuffer().fillWithByte(0, 16).getBytes();
      var addr = UTIL.bytesToIP(bytes);
      ASSERT.equal(addr, '::');
    });

    it('should convert IPv6 ::1 byte address to canonical textual representation (RFC 5952)', function() {
      var addr = '::1';
      var bytes = UTIL.bytesFromIP(addr);
      var addr = UTIL.bytesToIP(bytes);
      ASSERT.equal(addr, '::1');
    });

    it('should convert IPv6 1:: byte address to canonical textual representation (RFC 5952)', function() {
      var addr = '1::';
      var bytes = UTIL.bytesFromIP(addr);
      var addr = UTIL.bytesToIP(bytes);
      ASSERT.equal(addr, '1::');
    });

    it('should convert IPv6 0:0:0:0:0:0:0:1 byte address to canonical textual representation (RFC 5952)', function() {
      var addr = '0:0:0:0:0:0:0:1';
      var bytes = UTIL.bytesFromIP(addr);
      var addr = UTIL.bytesToIP(bytes);
      ASSERT.equal(addr, '::1');
    });

    it('should convert IPv6 1:0:0:0:0:0:0:0 byte address to canonical textual representation (RFC 5952)', function() {
      var addr = '1:0:0:0:0:0:0:0';
      var bytes = UTIL.bytesFromIP(addr);
      var addr = UTIL.bytesToIP(bytes);
      ASSERT.equal(addr, '1::');
    });

    it('should convert IPv6 1::1 byte address to canonical textual representation (RFC 5952)', function() {
      var addr = '1::1';
      var bytes = UTIL.bytesFromIP(addr);
      var addr = UTIL.bytesToIP(bytes);
      ASSERT.equal(addr, '1::1');
    });

    it('should convert IPv6 1:0:0:0:0:0:0:1 byte address to canonical textual representation (RFC 5952)', function() {
      var addr = '1:0:0:0:0:0:0:1';
      var bytes = UTIL.bytesFromIP(addr);
      var addr = UTIL.bytesToIP(bytes);
      ASSERT.equal(addr, '1::1');
    });

    it('should convert IPv6 1:0000:0000:0000:0000:0000:0000:1 byte address to canonical textual representation (RFC 5952)', function() {
      var addr = '1:0000:0000:0000:0000:0000:0000:1';
      var bytes = UTIL.bytesFromIP(addr);
      var addr = UTIL.bytesToIP(bytes);
      ASSERT.equal(addr, '1::1');
    });

    it('should convert IPv6 1:0:0:1:1:1:0:1 byte address to canonical textual representation (RFC 5952)', function() {
      var addr = '1:0:0:1:1:1:0:1';
      var bytes = UTIL.bytesFromIP(addr);
      var addr = UTIL.bytesToIP(bytes);
      ASSERT.equal(addr, '1::1:1:1:0:1');
    });

    it('should convert IPv6 1:0:1:1:1:0:0:1 byte address to canonical textual representation (RFC 5952)', function() {
      var addr = '1:0:1:1:1:0:0:1';
      var bytes = UTIL.bytesFromIP(addr);
      var addr = UTIL.bytesToIP(bytes);
      ASSERT.equal(addr, '1:0:1:1:1::1');
    });

    it('should convert IPv6 2001:db8:0:1:1:1:1:1 byte address to canonical textual representation (RFC 5952)', function() {
      var addr = '2001:db8:0:1:1:1:1:1';
      var bytes = UTIL.bytesFromIP(addr);
      var addr = UTIL.bytesToIP(bytes);
      ASSERT.equal(addr, '2001:db8:0:1:1:1:1:1');
    });

    it('should convert "foo" to its UTF-8 representation', function() {
      if(typeof Uint8Array === 'undefined') {
        return;
      }
      var result = UTIL.text.utf8.encode('foo');
      ASSERT.equal(result.byteLength, 3);
      ASSERT.equal(result[0], 102);
      ASSERT.equal(result[1], 111);
      ASSERT.equal(result[2], 111);
    });

    it('should convert "foo" from its UTF-8 representation', function() {
      if(typeof Uint8Array === 'undefined') {
        return;
      }
      var bytes = new Uint8Array([102, 111, 111]);
      var result = UTIL.text.utf8.decode(bytes);
      ASSERT.equal(result, 'foo');
    });

    it('should convert "\ud83c\udc00" to its UTF-8 representation', function() {
      if(typeof Uint8Array === 'undefined') {
        return;
      }
      var result = UTIL.text.utf8.encode('\ud83c\udc00');
      ASSERT.equal(result.byteLength, 4);
      ASSERT.equal(result[0], 240);
      ASSERT.equal(result[1], 159);
      ASSERT.equal(result[2], 128);
      ASSERT.equal(result[3], 128);
    });

    it('should convert "\ud83c\udc00" from its UTF-8 representation', function() {
      if(typeof Uint8Array === 'undefined') {
        return;
      }
      var bytes = new Uint8Array([240, 159, 128, 128]);
      var result = UTIL.text.utf8.decode(bytes);
      ASSERT.equal(result, '\ud83c\udc00');
    });

    it('should convert "foo" to its UTF-16 representation', function() {
      if(typeof Uint8Array === 'undefined') {
        return;
      }
      var result = UTIL.text.utf16.encode('foo');
      ASSERT.equal(result.byteLength, 6);
      ASSERT.equal(result[0], 102);
      ASSERT.equal(result[1], 0);
      ASSERT.equal(result[2], 111);
      ASSERT.equal(result[3], 0);
      ASSERT.equal(result[4], 111);
      ASSERT.equal(result[5], 0);
    });

    it('should convert "foo" from its UTF-16 representation', function() {
      if(typeof Uint8Array === 'undefined') {
        return;
      }
      var bytes = new Uint8Array([102, 0, 111, 0, 111, 0]);
      var result = UTIL.text.utf16.decode(bytes);
      ASSERT.equal(result, 'foo');
    });

    it('should convert "\ud83c\udc00" to its UTF-16 representation', function() {
      if(typeof Uint8Array === 'undefined') {
        return;
      }
      var result = UTIL.text.utf16.encode('\ud83c\udc00');
      ASSERT.equal(result.byteLength, 4);
      ASSERT.equal(result[0], 60);
      ASSERT.equal(result[1], 216);
      ASSERT.equal(result[2], 0);
      ASSERT.equal(result[3], 220);
    });

    it('should convert "\ud83c\udc00" from its UTF-16 representation', function() {
      if(typeof Uint8Array === 'undefined') {
        return;
      }
      var bytes = new Uint8Array([60, 216, 0, 220]);
      var result = UTIL.text.utf16.decode(bytes);
      ASSERT.equal(result, '\ud83c\udc00');
    });
  });
})();
