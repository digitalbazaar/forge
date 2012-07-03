var forge = require('../../js/forge');

exports.testExpandKey = function(test) {
  var key = '88bca90e90875a7f0f79c384627bafb2';
  key = new forge.util.ByteBuffer(forge.util.hexToBytes(key));

  var exp = '71ab26462f0b9333609d4476e48ab72438c2194b70a47085d84b6af1dc72119023b94fe80aee2b6b45f27f923d9be1570da3ce8b16ad7f78db166ffbc28a836a4392cf0b748085dae4b69bdc2a4679cdfc09d84317016987e0c5b765c91dc612b1f44d7921b3e2c46447508bd2ac02e119e0f42a89c719675da320cf3e8958cd';
  var res = forge.rc2.expandKey(key);
  test.equal(res.toHex(), exp);
  test.done();
};

exports.testExpandKey40 = function(test) {
  var key = '88bca90e90';
  key = new forge.util.ByteBuffer(forge.util.hexToBytes(key));

  var exp = 'af136d2243b94a0878d7a604f8d6d9fd64a698fd6ebc613e641f0d1612055ef6cb55966db8f32bfd9246dae99880be8a91433adf54ea546d9daad62db7a55f6c7790aa87ba67de0e9ea9128dfc7ccdddd7c47c33d2bb7f823729977f083b5dc1f5bb09000b98e12cdaaf22f80dcc88c37d2c2fd80402f8a30a9e41d356669471';
  var res = forge.rc2.expandKey(key, 40);
  test.equal(res.toHex(), exp);
  test.done();
}

exports.testEncryptZerosECB = function(test) {
  var key = '88bca90e90875a7f0f79c384627bafb2';
  key = new forge.util.ByteBuffer(forge.util.hexToBytes(key));

  var input = new forge.util.ByteBuffer();
  input.fillWithByte(0, 8);

  var cipher = forge.rc2.startEncrypting(key, null, null)
  cipher.update(input);
  cipher.finish();

  var res = '2269552ab0f85ca6e35b3b2ce4e02191';
  test.equal(cipher.output.toHex(), res);
  test.done();
}

exports.testEncryptDataECB = function(test) {
  var key = '88bca90e90875a7f0f79c384627bafb2';
  key = new forge.util.ByteBuffer(forge.util.hexToBytes(key));

  var input = new forge.util.ByteBuffer('vegan');

  var cipher = forge.rc2.startEncrypting(key, null, null)
  cipher.update(input);
  cipher.finish();

  var res = '2194adaf4d517e3a';
  test.equal(cipher.output.toHex(), res);
  test.done();
}

exports.testEncryptDataCBC = function(test) {
  var key = '88bca90e90875a7f0f79c384627bafb2';
  key = new forge.util.ByteBuffer(forge.util.hexToBytes(key));

  var iv = '0123456789abcdef';
  iv = new forge.util.ByteBuffer(forge.util.hexToBytes(iv));

  var input = new forge.util.ByteBuffer('revolution');

  var cipher = forge.rc2.startEncrypting(key, iv, null)
  cipher.update(input);
  cipher.finish();

  var res = '50cfd16e0fd7f20b17a622eb2a469b7e';
  test.equal(cipher.output.toHex(), res);
  test.done();
}
