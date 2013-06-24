// RSA's test vectors for Forge's RSA-OAEP implementation:
// http://www.rsa.com/rsalabs/node.asp?id=2125
//
// ... plus a few other tests

var assert = require('assert');
var forge = require('../js/forge');

function _bytesToBigInteger(bytes) {
    var buffer = forge.util.createBuffer(bytes);
    var hex = buffer.toHex();
    return new BigInteger(hex, 16);
}

function _base64ToBn(s) {
    var decoded = forge.util.decode64(s);
    return _bytesToBigInteger(decoded);
}

function checkOAEPEncrypt(pubkey, privateKey, message, seed, expected) {
  message = forge.util.decode64(message);
  seed = forge.util.decode64(seed);
  var ciphertext = forge.pkcs1.rsa_oaep_encrypt(pubkey, message, '', seed);
  assert.equal(expected, forge.util.encode64(ciphertext));

  var decrypted = forge.pkcs1.rsa_oaep_decrypt(privateKey, ciphertext);
  assert.equal(message, decrypted);

  // Test with default label and generating a seed
  ciphertext = forge.pkcs1.rsa_oaep_encrypt(pubkey, message);
  decrypted = forge.pkcs1.rsa_oaep_decrypt(privateKey, ciphertext);
  assert.equal(message, decrypted);
}

function decodeBase64PublicKey(modulus, exponent) {
  modulus = _base64ToBn(modulus);
  exponent = _base64ToBn(exponent);
  return forge.pki.setRsaPublicKey(modulus, exponent);
}

function decodeBase64PrivateKey(modulus, exponent, d, p, q, dP, dQ, qInv) {
  modulus = _base64ToBn(modulus);
  exponent = _base64ToBn(exponent);
  d = _base64ToBn(d);
  p = _base64ToBn(p);
  q = _base64ToBn(q);
  dP = _base64ToBn(dP);
  dQ = _base64ToBn(dQ);
  qInv = _base64ToBn(qInv);
  return forge.pki.setRsaPrivateKey(modulus, exponent, d, p, q, dP, dQ, qInv);
}

function makeKey() {
  var modulus, exponent, d, p, q, dP, dQ, qInv, pubkey, privateKey, message, seed, encrypted;

  // Example 1: A 1024-bit RSA Key Pair
  modulus = 'qLOyhK+OtQs4cDSoYPFGxJGfMYdjzWxVmMiuSBGh4KvEx+CwgtaTpef87Wdc9GaFEncsDLxkp0LGxjD1M8jMcvYq6DPEC/JYQumEu3i9v5fAEH1VvbZi9cTg+rmEXLUUjvc5LdOq/5OuHmtme7PUJHYW1PW6ENTP0ibeiNOfFvs=';
  exponent = 'AQAB';
  d = 'UzOc/befyEZqZVxzFqyoXFX9j23YmP2vEZUX709S6P2OJY35P+4YD6DkqylpPNg7FSpVPUrE0YEri5+lrw5/Vf5zBN9BVwkm8zEfFcTWWnMsSDEW7j09LQrzVJrZv3y/t4rYhPhNW+sEck3HNpsx3vN9DPU56c/N095lNynq1dE=';
  p = '0yc35yZ//hNBstXA0VCoG1hvsxMr7S+NUmKGSpy58wrzi+RIWY1BOhcu+4AsIazxwRxSDC8mpHHcrSEurHyjnQ==';
  q = 'zIhT0dVNpjD6wAT0cfKBx7iYLYIkpJDtvrM9Pj1cyTxHZXA9HdeRZC8fEWoN2FK+JBmyr3K/6aAw6GCwKItddw==';
  dP = 'DhK/FxjpzvVZm6HDiC/oBGqQh07vzo8szCDk8nQfsKM6OEiuyckwX77L0tdoGZZ9RnGsxkMeQDeWjbN4eOaVwQ==';
  dQ = 'lSl7D5Wi+mfQBwfWCd/U/AXIna/C721upVvsdx6jM3NNklHnkILs2oZu/vE8RZ4aYxOGt+NUyJn18RLKhdcVgw==';
  qInv = 'T0VsUCSTvcDtKrdWo6btTWc1Kml9QhbpMhKxJ6Y9VBHOb6mNXb79cyY+NygUJ0OBgWbtfdY2h90qjKHS9PvY4Q==';
  pubkey = decodeBase64PublicKey(modulus, exponent);
  privateKey = decodeBase64PrivateKey(modulus, exponent, d, p, q, dP, dQ, qInv);

  return {publicKey: pubkey, privateKey: privateKey};
}

function testCorruptDecrypt() {
  var keys = makeKey();

  // provide the seed to test the same input each time
  var seed = forge.util.decode64('JRTfRpV1WmeyiOr0kFw27sZv0v0=');

  // Test decrypting corrupted data: flip every bit in the message
  // this tests the padding error handling
  var encrypted = forge.pkcs1.rsa_oaep_encrypt(keys.publicKey, 'datadatadatadata', '', seed);
  for (var bit = 0; bit < encrypted.length * 8; bit++) {
    var byteIndex = bit / 8;
    var bitInByte = bit % 8;

    var out = encrypted.substring(0, byteIndex);
    var mask = 0x1 << bitInByte;
    out += String.fromCharCode(encrypted.charCodeAt(byteIndex) ^ mask);
    out += encrypted.substring(byteIndex + 1);

    try {
      output = forge.pkcs1.rsa_oaep_decrypt(keys.privateKey, out);
      console.log('Error: expected an exception!', bit, byteIndex, bitInByte, mask);
      console.log(output);
      assert(false);
    } catch (e) {
      if (e.message != 'Decryption error: invalid padding') {
        throw e;
      }
    }
    process.stdout.write('.');
  }
}

// Test leading zero bytes since unpadding looks for them
function testZeroMessage() {
  var keys = makeKey();

  var message = '';
  for (var i = 0; i < 80; i++) {
    message += '\x00';
  }

  var ciphertext = forge.pkcs1.rsa_oaep_encrypt(keys.publicKey, message);
  var decrypted = forge.pkcs1.rsa_oaep_decrypt(keys.privateKey, ciphertext);
  assert.equal(message, decrypted);
}

function testOAEP() {
  var modulus, exponent, d, p, q, dP, dQ, qInv, pubkey, privateKey, message, seed, encrypted;

  // Example 1: A 1024-bit RSA Key Pair
  // Components of the RSA Key Pair
  modulus = 'qLOyhK+OtQs4cDSoYPFGxJGfMYdjzWxVmMiuSBGh4KvEx+CwgtaTpef87Wdc9GaFEncsDLxkp0LGxjD1M8jMcvYq6DPEC/JYQumEu3i9v5fAEH1VvbZi9cTg+rmEXLUUjvc5LdOq/5OuHmtme7PUJHYW1PW6ENTP0ibeiNOfFvs=';
  exponent = 'AQAB';
  d = 'UzOc/befyEZqZVxzFqyoXFX9j23YmP2vEZUX709S6P2OJY35P+4YD6DkqylpPNg7FSpVPUrE0YEri5+lrw5/Vf5zBN9BVwkm8zEfFcTWWnMsSDEW7j09LQrzVJrZv3y/t4rYhPhNW+sEck3HNpsx3vN9DPU56c/N095lNynq1dE=';
  p = '0yc35yZ//hNBstXA0VCoG1hvsxMr7S+NUmKGSpy58wrzi+RIWY1BOhcu+4AsIazxwRxSDC8mpHHcrSEurHyjnQ==';
  q = 'zIhT0dVNpjD6wAT0cfKBx7iYLYIkpJDtvrM9Pj1cyTxHZXA9HdeRZC8fEWoN2FK+JBmyr3K/6aAw6GCwKItddw==';
  dP = 'DhK/FxjpzvVZm6HDiC/oBGqQh07vzo8szCDk8nQfsKM6OEiuyckwX77L0tdoGZZ9RnGsxkMeQDeWjbN4eOaVwQ==';
  dQ = 'lSl7D5Wi+mfQBwfWCd/U/AXIna/C721upVvsdx6jM3NNklHnkILs2oZu/vE8RZ4aYxOGt+NUyJn18RLKhdcVgw==';
  qInv = 'T0VsUCSTvcDtKrdWo6btTWc1Kml9QhbpMhKxJ6Y9VBHOb6mNXb79cyY+NygUJ0OBgWbtfdY2h90qjKHS9PvY4Q==';
  pubkey = decodeBase64PublicKey(modulus, exponent);
  privateKey = decodeBase64PrivateKey(modulus, exponent, d, p, q, dP, dQ, qInv);

  // RSAES-OAEP Encryption Example 1.1
  message = 'ZigZThIHPbA7qUzanvlTI5fVDbp5uYcASv7+NA==';
  seed = 'GLd26iEGnWl3ajPpa61I4d2gpe8=';
  encrypted = 'NU/me0oSbV01/jbHd3kaP3uhPe9ITi05CK/3IvrUaPshaW3pXQvpEcLTF0+K/MIBA197bY5pQC3lRRYYwhpTX6nXv8W43Z/CQ/jPkn2zEyLW6IHqqRqZYXDmV6BaJmQm2YyIAD+Ed8EicJSg2foejEAkMJzh7My1IQA11HrHLoo=';
  checkOAEPEncrypt(pubkey, privateKey, message, seed, encrypted);

  // RSAES-OAEP Encryption Example 1.2
  message = 'dQxAR/VH6OQUEYVlIymKybriRe+vE5f75W+d1Q==';
  seed = 'DMdCzkqbfzL5UbyyUe/ZJf5P418=';
  encrypted = 'ZA2xrMWOBWj+VAfl+bcB3/jDyR5xbFNvx/zsbLW3HBFlmI1KJ54Vd9cw/Hopky4/AMgVFSNtjY4xAXp6Cd9DUtkEzet5qlg63MMeppikwFKD2rqQib5UkfZ8Gk7kjcdLu+ZkOu+EZnm0yzlaNS1e0RWRLfaW/+BwKTKUbXFJK0Q=';
  checkOAEPEncrypt(pubkey, privateKey, message, seed, encrypted);

  // RSAES-OAEP Encryption Example 1.3
  message = '2Urggy5kRc5CMxywbVMagrHbS6rTD3RtyRbfJNTjwkUf/1mmQj6w4dAtT+ZGz2md/YGMbpewUQ==';
  seed = 'JRTfRpV1WmeyiOr0kFw27sZv0v0=';
  encrypted = 'Qjc27QNfYCavJ2w1wLN0GzZeX3bKCRtOjCni8L7+5gNZWqgyLWAtLmJeleuBsvHJck6CLsp224YYzwnFNDUDpDYINbWQO8Y344efsF4O8yaF1a7FBnzXzJb+SyZwturDBmsfz1aGtoWJqvt9YpsC2PhiXKODNiTUgA+wgbHPlOs=';
  checkOAEPEncrypt(pubkey, privateKey, message, seed, encrypted);

  // RSAES-OAEP Encryption Example 1.4
  message = 'UuZQ2Y5/KgSLT4aFIVO5fgHdMW80ahn2eoU=';
  seed = 'xENaPhoYpotoIENikKN877hds/s=';
  encrypted = 'RerUylUeZiyYAPGsqCg7BSXmq64wvktKunYvpA/T044iq+/Gl5T267vAXduxEhYkfS9BL9D7qHxuOs2IiBNkb9DkjnhSBPnD9z1tgjlWJyLd3Ydx/sSLg6Me5vWSxM/UvIgXTzsToRKq47n3uA4PxvclW6iA3H2AIeIq1qhfB1U=';
  checkOAEPEncrypt(pubkey, privateKey, message, seed, encrypted);

  // RSAES-OAEP Encryption Example 1.5
  message = 'jaif2eX5dKKf7/tGK0kYD2z56AI=';
  seed = 'sxjELfO+D4P+qCP1p7R+1eQlo7U=';
  encrypted = 'NvbjTZSo002qy6M6ITnQCthak0WoYFHnMHFiAFa5IOIZAFhVohOg8jiXzc1zG0UlfHd/6QggK+/dC1g4axJE6gz1OaBdXRAynaROEwMP12Dc1kTP7yCU0ZENP0M+HHxt0YvB8t9/ZD1mL7ndN+rZBZGQ9PpmyjnoacTrRJy9xDk=';
  checkOAEPEncrypt(pubkey, privateKey, message, seed, encrypted);

  // RSAES-OAEP Encryption Example 1.6
  message = 'JlIQUIRCcQ==';
  seed = '5OwJgsIzbzpnf2o1YXTrDOiHq8I=';
  encrypted = 'Qs7iYXsezqTbP0gpOG+9Ydr78DjhgNg3yWNm3yTAl7SrD6xr31kNghyfEGQuaBrQW414s3jA9Gzi+tY/dOCtPfBrB11+tfVjb41AO5BZynYbXGK7UqpFAC6nC6rOCN7SQ7nYy9YqaK3iZYMrVlZOQ6b6Qu0ZmgmXaXQt8VOeglU=';
  checkOAEPEncrypt(pubkey, privateKey, message, seed, encrypted);

  // Example 2: A 1025-bit RSA Key Pair
  // Components of the RSA Key Pair
  modulus = 'AZR8f86QQl9HJ55whR8l1eYjFv6KHfGTcePmKOJgVD5JAe9ggfaMC4FBGQ0q6Nq6fRJQ7G22NulE7Dcih3x8HQpn8UsWlMXwN5RRpD5Joy3eg2cLc9qRocmbwjtDamAFXGEPC6+ZwaB5VluVo/FSZjLR1Npg8g7aJeZTxPACdm9F';
  exponent = 'AQAB';
  d = 'CCPyD6212okIip0AiT4h+kobEfvJPGSjvguq6pf7O5PD/3E3BMGcljwdEHqumQVHOfeeAuGG3ob4em3e/qbYzNHTyBpHv6clW+IGAaSksvCKFnteJ51xWxtFW91+qyRZQdl2i5rO+zzNpZUto87nJSW0UBZjqO4VyemS2SRi/jk=';
  p = 'AVnb3gSjPvBvtgi4CxkPTT4ivME6yOSggQM6v6QW7bCzOKoItXMJ6lpSQOfcblQ3jGlBTDHZfdsfQG2zdpzEGkM=';
  q = 'AStlLzBAOzi0CZX9b/QaGsyK2nA3Mja3IC05su4wz7RtsJUR9vMHzGHMIWBsGKdbimL4It8DG6DfDa/VUG9Wi9c=';
  dP = 'Q271CN5zZRnC2kxYDZjILLdFKj+1763Ducd4mhvGWE95Wt270yQ5x0aGVS7LbCwwek069/U57sFXJIx7MfGiVQ==';
  dQ = 'ASsVqJ89+ys5Bz5z8CvdDBp7N53UNfBc3eLv+eRilIt87GLukFDV4IFuB4WoVrSRCNy3XzaDh00cpjKaGQEwZv8=';
  qInv = 'AnDbF9WRSwGNdhGLJDiac1Dsg2sAY6IXISNv2O222JtR5+64e2EbcTLLfqc1bCMVHB53UVB8eG2e4XlBcKjI6A==';
  pubkey = decodeBase64PublicKey(modulus, exponent);
  privateKey = decodeBase64PrivateKey(modulus, exponent, d, p, q, dP, dQ, qInv);

  // RSAES-OAEP Encryption Example 2.1
  message = 'j/AMqmBccCgwY02abD1CxlK1jPHZL+xXC+7n';
  seed = 'jEB7XsKJnlCZxT6M55O/lOcbF4I=';
  encrypted = 'AYGviSK5/LTXnZLr4ZgVmS/AwUOdi81JE5ig9K06Mppb2ThVYNtTJoPIt9oE5LEq7Wqs30ccNMnNqJGt3MLfNFZlOqY4Lprlm1RFUlfrCZ1WK74QRT8rbRPFnALhDx+Ku12g0FcJMtrPLQkB23KdD+/MBU5wlo6lQMgbBLyu/nIO';
  checkOAEPEncrypt(pubkey, privateKey, message, seed, encrypted);

  // RSAES-OAEP Encryption Example 2.2
  message = 'LQ==';
  seed = 'tgDPPC5QbX8Wd4yRDTqLAD7uYdU=';
  encrypted = 'AYdZ/x32OyeSQQViMUQWqK6vKsY0tG+UCrgtZNvxZe7jMBHadJ1Lq24vzRgSnJ5JJ32EUxErQpoiKoRxsHCZOZjnWIYcTT9tdJ2RxCkNMyx6SrP36jX/OgfUl8lV/w/8lQBrYsbSloENm/qwJBlseTQBLC35eO8pmrojmUDLoQJF';
  checkOAEPEncrypt(pubkey, privateKey, message, seed, encrypted);

  // RSAES-OAEP Encryption Example 2.3
  message = 'dPyIxRvJD3evnV6aSnATPUtOCzTaPDfH744=';
  seed = 'pzdoruqpH52MHtb50rY0Z/B8yuM=';
  encrypted = 'AYgCurBMYDJegcSWIxHyvnwq3OkwQaAHGciPlXV18sefG3vIztEVxwazEcCKLZhso7apM2sUfCnG8ilAnd7GUb0f3VoLf2EMmTf9tKOnYjZLizIGtOpIX9CY0I9j1KqLsml9Ant1DDLX906vUYDS6bZrF8svpVUjvCgNoQ0UviBT';
  checkOAEPEncrypt(pubkey, privateKey, message, seed, encrypted);

  // RSAES-OAEP Encryption Example 2.4
  message = 'p+sqUDaTHSfU6JEybZlpL/rdqb9+/T405iLErcCF9yHf6IUHLHiiA7FRc5vlQPqMFToQ8Ao=';
  seed = 'mns7DnCL2W+BkOyrT7mys4BagVY=';
  encrypted = 'AKRXjLwXYximOPun0B3xV0avRNT2zZbX58SVy/QlsJxknTK/iG2kj7r5iaIRcYfK+x+1gDF2kOPM1EaSC3r4KzHbWATYfQFRSsv6kVbngvhn9r7ZRJ4OmiwJvOzGqgh2NpZeNLPsdm8v4uQwGKL93rFAYWoOnYLlMxAk7gZS/HZB';
  checkOAEPEncrypt(pubkey, privateKey, message, seed, encrypted);

  // RSAES-OAEP Encryption Example 2.5
  message = 'LvKwZvhUwz873LtZlKQ15z1sbA==';
  seed = '6zzrvErcFrtI6IyK7A40r39Cf9M=';
  encrypted = 'AOvF9f2nfP2tPINkGpAl531y2Kb7M6gQ9ZUPjXTHPo2THoY02GqxJGJWrge2AFtxt/L7mDUSGDMc5puP+9ydoIu8nHBPh23rnfn8LsBlyth/kJCweswXqn+ZeyespIgG6Jf3cdlRQf5FJtilMBtnhifvq3B/1A++vW55KiVhPnrs';
  checkOAEPEncrypt(pubkey, privateKey, message, seed, encrypted);

  // RSAES-OAEP Encryption Example 2.6
  message = 'in+zRMi2yyzy7x9kP5oyGPbhm7qJwA==';
  seed = 'TEXPTVfJjj1tIJWtxRxInrUN/4Q=';
  encrypted = 'AQg57CDCe5BS5Vvvubd+b8JukHXXpUN4xkar31HkRb1XFd6BeJ9W8YA9kXB2Sp6Ty3h5hpQCPuc5POBLxdj4xaUsFx1Dg346ymL2CesKpf+wlg7wQZjddU9X9/vmq/dlzxGLTKRDsjtaqyZvlSMmrEWBEAZEMl+LchrNXQT/FO86';
  checkOAEPEncrypt(pubkey, privateKey, message, seed, encrypted);

  // Example 3: A 1026-bit RSA Key Pair
  // Components of the RSA Key Pair
  modulus = 'ArWP7AOahgcApNe2Ri+T5s3UkRYd3XT06BC0DjwWUgBqXCd7J3TBEwWky6taeO+lfheobfej+jb8Sx0iSfIux8LdakYyMqzOqQbWbr6AtXBLEHKdpvgzI0q7Xv3UopLL+tM7TTP6ehS4w5e1bjrNISA0KLd836M6bacGs9iw/EPp';
  exponent = 'AQAB';
  d = 'FbSKW1aDqUZw4jtXGPgU+g4T+FA49QcRGCy6YVEFgfPSLH4jLvk34i5VHWi4bi+MsarYvi5Ij13379J54/Vo1Orzb4DPcUGs5g/MkRP7bEqEH9ULvHxRL/y+/yFIeqgR6zyoxiAFNGqG3oa/odipSP0/NIwi6q3zM8PObOEyCP0=';
  p = 'Ab8B0hbXNZXPAnDCvreNQKDYRH0x2pGamD9+6ngbd9hf43Gz6Tc+e2khfTFQoC2JWN5/rZ1VUWCVi0RUEn4Ofq8=';
  q = 'AY0zmWWBZts4KYFteylUFnWenJGYf1stiuzWOwS0i9ey/PIpu3+KbciLoT3S45rVW20aBhYHCPlwC+gLj9N0TOc=';
  dP = 'BsCiSdIKby7nXIi0lNU/aq6ZqkJ8iMKLFjp2lEXl85DPQMJ0/W6mMppc58fOA6IVg5buKnhFeG4J4ohalyjk5Q==';
  dQ = '0dJ8Kf7dkthsNI7dDMv6wU90bgUc4dGBHfNdYfLuHJfUvygEgC9kJxh7qOkKivRCQ7QHmwNEXmAuKfpRk+ZP6Q==';
  qInv = 'jLL3Vr2JQbHTt3DlrTHuNzsorNpp/5tvQP5Xi58a+4WDb5Yn03rP9zwneeY0uyYBHCyPfzNhriqepl7WieNjmg==';
  pubkey = decodeBase64PublicKey(modulus, exponent);
  privateKey = decodeBase64PrivateKey(modulus, exponent, d, p, q, dP, dQ, qInv);

  // RSAES-OAEP Encryption Example 3.1
  message = 'CHggtWno+o0=';
  seed = 'jO1rGWKQgFeQ6QkHQBXmogsMSJQ=';
  encrypted = 'AmoEhdlq69lrQ4IIUJm5Yuaivew9kMjbYl4UNy3oXi1be6q2XI+vkbtVBPtJWvzlyYiz9qUuIOHWy9NWbFzR8rgxi7VCzA6iXEqrmTKvogdg6t3seEOWoH6g7yTU5vTTflBSp6MeFGqkgKERu+kmQBMH4A9BADOEK22C/lzk366A';
  checkOAEPEncrypt(pubkey, privateKey, message, seed, encrypted);

  // RSAES-OAEP Encryption Example 3.2
  message = 'RlOsrxcZYLAfUqe+Y6OrIdw2jsQ7UNguw3geBA==';
  seed = 'tCkdZWdVCEjMFWlnyAm6q2ylB/A=';
  encrypted = 'Ak24nHgCmJvgeDhHhjCElBvyCddhmH44+Xy19vG8iNpypQtz668RyHnE+V3ze4ULj2XXYi4lsbiJ6A/oC6yiBp1uDh2CmVP8RZBp3pjql5i0UeVX6Zq/j+PZzPkJbrvz5SVdO04cbS7K3wZ6NZ7qhkBazUfV4WVRfMr9R9bb7kv1';
  checkOAEPEncrypt(pubkey, privateKey, message, seed, encrypted);

  // RSAES-OAEP Encryption Example 3.3
  message = '2UzQ4I+kBO2J';
  seed = 'zoko9gWVWCVACLrdl5T63NL9H2U=';
  encrypted = 'Ajm85oEDJEFSiHfW0ci7KKo7yX8d9YRWNhiZV5doOETKhmZHMvS+16CqsIOqq/tyOPWC4wlYwgJOROVwQ7l5UP1UPal3yQzd5TN9YYRC+Z5g13g6tZzm3Z1pxHrR6WK+wi0FiVz/jT9k7VJh2SsmeFEDk0hJkLo/fwaBiub/zoo6';
  checkOAEPEncrypt(pubkey, privateKey, message, seed, encrypted);

  // RSAES-OAEP Encryption Example 3.4
  message = 'bMZBtrYeb5Y5dNrSOpATKE7x';
  seed = 'bil59S1oFKV9g7CQBUiI8RmluaM=';
  encrypted = 'AplMYq/Xb0mLof0s9kKFf8qB9Dc8sI8cuu5vAlw7UStCw+h3kRNHZkgDnb4Ek/kkYpL6wolQYA58DzLt+cgbnexFw73gzI2IR1kBaZB7fcWZHOspuwcU1hPZbfDxLsXY01B8jueueN2D8hb6Yd4QA2OspIp+kUrp9C3fvpQ7Cdmg';
  checkOAEPEncrypt(pubkey, privateKey, message, seed, encrypted);

  // RSAES-OAEP Encryption Example 3.5
  message = '31FRgyth9PJYkftBcvMo0u3fg3H/z9vpl5OSlfMOymkYAXz9oRU796avh1kyIw==';
  seed = 'LXYL/jjFneNM3IuMeKOOZihKLSc=';
  encrypted = 'AWIEL/aWlZKmFnAxgRojmDTOY4q/VP7IuZR4Eir+LuZ/jFsYsDOYBb/bxaTmcgs3xZz7qUJGTFl/9TKhGYIVRf0uWbEU5h2vcYIFKfUCnPUklUMnw07F5vW6fvzE3pQ6uK1O14exRUMp9w23mKOo9NkvgnTispSK3mJ86O4z5Dxg';
  checkOAEPEncrypt(pubkey, privateKey, message, seed, encrypted);

  // RSAES-OAEP Encryption Example 3.6
  message = 'PDutiTxUSm1SCrAiMZGIyNUEt6eIuFCQO4WXLqoYVS4RNKetYJiCYlT/erZys9jrMVj6xtTLrvE=';
  seed = '8XR3nF/Tz+AHuty3o2ybVb/Pvw4=';
  encrypted = 'ABEgUeddBklDvER4B15DSC/VnO4Ged5ok+7DqUPapJC5aRyT38BGS2YjufPb0+cAgyZPA0s3T3QWThoAdjcl5XR0S6C524NDTzHflvbiom9tjro0i9RobCI4rAfDeqw3hdHH7qL4Gf2RSReY7Y6c715Dt4Gw4CduN8Q/+UktAFcw';
  checkOAEPEncrypt(pubkey, privateKey, message, seed, encrypted);

  // Example 4: A 1027-bit RSA Key Pair
  // Components of the RSA Key Pair
  modulus = 'BRJAtswABPpI0BNGccB4x8jew7Pi8lvCVkRnM52ziFPQa4XupbLeNTv/QqwuRryX+uaslhjalTelyPVTweNXYlmR1hCNzXiF+zolQT9T78rZSMs1zZua6cHGdibRE9V93kxb6na7W7felsANBzculoWm11z50jn6FI1wkxtfP7A5';
  exponent = 'AQAB';
  d = 'BBH/yjt8penpvn/jioUQXjU4ltsFxXlq7NKnJRYes2UchimpuGK5BNewx7N/jLWhwrVAAQGKAKHrLK/k7k6UksNIvCvtq0ueu/Bk6O/zIrkAn47sZTkF9A34ijzcSdRWf3VifUGspiQSm0agt8aY5eZfK3uhAsdJoQE1tlQNBAE=';
  p = 'AnRYwZ7BY2kZ5zbJryXWCaUbj1YdGca/aUPdHuGriko/IyEAvUC4jezGuiNVSLbveSoRyd6CPQp5IscJW266VwE=';
  q = 'AhDumzOrYXFuJ9JRvUZfSzWhojLi2gCQHClL8iNQzkkNCZ9kK1N1YS22O6HyA4ZJK/BNNLPCK865CdE0QbU7UTk=';
  dP = 'OfoCi4JuiMESG3UKiyQvqaNcW2a9/R+mN9PMSKhKT0V6GU53J+Sfe8xuWlpBJlf8RwxzIuvDdBbvRYwweowJAQ==';
  dQ = 'AV2ZqEGVlDl5+p4b4sPBtp9DL0b9A+R9W++7v9ax0Tcdg++zMKPgIJQrL+0RXl0CviT9kskBnRzs1t1M8eVMyJk=';
  qInv = 'AfC3AVFws/XkIiO6MDAcQabYfLtw4wy308Z9JUc9sfbL8D4/kSbj6XloJ5qGWywrQmUkz8UqaD0x7TDrmEvkEro=';
  pubkey = decodeBase64PublicKey(modulus, exponent);
  privateKey = decodeBase64PrivateKey(modulus, exponent, d, p, q, dP, dQ, qInv);

  // RSAES-OAEP Encryption Example 4.1
  message = 'SoZglTTuQ0psvKP36WLnbUVeMmTBn2Bfbl/2E3xlxW1/s0TNUryTN089FmyfDG+cUGutGTMJctI=';
  seed = 'HKwZzpk971X5ggP2hSiWyVzMofM=';
  encrypted = 'BMzhlhSEXglBUqP+GOVOMzDETl77xkrhaIbLGGkBTMV4Gx+PngRThNARKhNcoNEunIio5AY0Ft6q44RPYNbpb+FVFF9FJbmjRDHKN2YYD3DhWl5djosaUW/4cGCfE/iWk1ztGIJ5pY7RPQcRQnfXXGVoYH4KsJL9gDoiPkqO4LGo';
  checkOAEPEncrypt(pubkey, privateKey, message, seed, encrypted);

  // RSAES-OAEP Encryption Example 4.2
  message = 'sK3E8/4R2lnOmSdz2QWZQ8AwRkl+6dn5oG3xFm20bZj1jSfsB0wC7ubL4kSci5/FCAxcP0QzCSUS7EaqeTdDyA==';
  seed = '9UXViXWF49txqgy42nbFHQMq6WM=';
  encrypted = 'AJe2mMYWVkWzA0hvv1oqRHnA7oWIm1QabwuFjWtll7E7hU60+DmvAzmagNeb2mV4yEH5DWRXFbKA03FDmS3RhsgLlJt3XK6XNw5OyXRDE2xtpITpcP/bEyOiCEeCHTsYOB3hO7SarqZlMMSkuCcfPq4XLNNm4H5mNvEBnSoortFe';
  checkOAEPEncrypt(pubkey, privateKey, message, seed, encrypted);

  // RSAES-OAEP Encryption Example 4.3
  message = 'v21C5wFwex0CBrDItFoccmQf8SiJIZqCveqWW155qWsNAWPtnVeOya2iDy+88eo8QInYNBm6gbDGDzYG2pk=';
  seed = 'rZl/7vcw1up75g0NxS5y6sv90nU=';
  encrypted = 'AwH5NenEery0isu+CYldn1lxrxSDnaT/lUF+5FPR/XcxkHK7cpfhtV11Yc2dG7JMGpo3xhmGQwgkKASHnYbr0AHc5Rg5deFQaYm3DlqDQ0FU1cv9aiR4fmDrDGWNKsGTMC0RksbmItShKtS1OSO8okbfMcY5XjdwLGp4rggfudBl';
  checkOAEPEncrypt(pubkey, privateKey, message, seed, encrypted);

  // RSAES-OAEP Encryption Example 4.4
  message = '+y7xEvXnZuuUAZKXk0eU974vb8HFjg==';
  seed = 'E2RU31cw9zyAen5A2MGjEqxbndM=';
  encrypted = 'AtEQrTCvtye+tpHdDPF9CvGh5/oMwEDsGkuiakLFnQp5ai4iyPNXzMmLZRms62gulF5iy3NGFKUpQHzUUr7j5E/s6EI8wZ5VVIuLmUuEnH7N5JM+dgN+HQzkQnWwhxDGjkMBMLkpcw7XfgmwFWQsVZPwTk/7lBB5gQKo6W/9/hHk';
  checkOAEPEncrypt(pubkey, privateKey, message, seed, encrypted);

  // RSAES-OAEP Encryption Example 4.5
  message = 'KMzUR7uehRZtq7nlt9GtrcS5058gTpbV5EDOmtkovBwihA==';
  seed = 'vKgFf4JLLqJX8oYUB+72PTMghoE=';
  encrypted = 'ANu4p0OdkO/ZGaN3xU+uj+EexYw7hYNi4jrRuKRDEHmQZrmTR6pSVpHSrcWNmwbjTyiMFwOQxfDhHAqjZFlZ8Y7nno8r6NesXCPQYfGN10uMXypY/LXrDFT5nwGoMkdWgpJTZYM0CUjXqMl8Ss0emNHincMg6XomBTKoqnp1ih7C';
  checkOAEPEncrypt(pubkey, privateKey, message, seed, encrypted);

  // RSAES-OAEP Encryption Example 4.6
  message = '8iJCdR7GsQ==';
  seed = 'Ln4eF/ZHtd3QM+FUcvkPaBLzrE4=';
  encrypted = 'AKX/pHaMi77K7i23fo8u7JlZWTNUVSCDXlun25ST0+F83e/mpfVnYkRxkI204tg6D77mBgj8hASVA7IjSgfcg7J7IoR62JIP9C9nTvebdigLACM9K1G4yycDqdQr+8glDJbsMsBR5X8bS6Uo24nDfkxU4n5uZKxpY1roh9lUFhmp';
  checkOAEPEncrypt(pubkey, privateKey, message, seed, encrypted);

  // Example 5: A 1028-bit RSA Key Pair
  // Components of the RSA Key Pair
  modulus = 'Cq3z+cEl5diR8xrESOmT3v5YD4ArRfnX8iulAh6cR1drWh5oAxup205tq+TZah1vPSZyaM/0CABfEY78rbmYiNHCNEZxZrKiuEmgWoicBgrA2gxfrotV8wm6YucDdC+gMm8tELARAhSJ/0l3cBkNiV/Tn1IpPDnv1zppi9q58Q7Z';
  exponent = 'AQAB';
  d = 'AlbrTLpwZ/LSvlQNzf9FgqNrfTHRyQmbshS3mEhGaiaPgPWKSawEwONkiTSgIGwEU3wZsjZkOmCCcyFE33X6IXWI95RoK+iRaCdtxybFwMvbhNMbvybQpDr0lXF/fVKKz+40FWH2/zyuBcV4+EcNloL5wNBy+fYGi1bViA9oK+LF';
  p = 'A7DTli9tF1Scv8oRKUNI3PDn45+MK8aCTyFktgbWh4YNrh5jI5PP7fUTIoIpBp4vYOSs1+YzpDYGP4I4X0iZNwc=';
  q = 'AuTDLi9Rcmm3ByMJ8AwOMTZffOKLI2uCkS3yOavzlXLPDtYEsCmC5TVkxS1qBTl95cBSov3cFB73GJg2NGrrMx8=';
  dP = 'AehLEZ0lFh+mewAlalvZtkXSsjLssFsBUYACmohiKtw/CbOurN5hYat83iLCrSbneX31TgcsvTsmc4ALPkM429U=';
  dQ = '65CqGkATW0zqBxl87ciBm+Hny/8lR2YhFvRlpKn0h6sS87pP7xOCImWmUpfZi3ve2TcuP/6Bo4s+lgD+0FV1Tw==';
  qInv = 'AS9/gTj5QEBi64WkKSRSCzj1u4hqAZb0i7jc6mD9kswCfxjngVijSlxdX4YKD2wEBxp9ATEsBlBi8etIt50cg8s=';
  pubkey = decodeBase64PublicKey(modulus, exponent);
  privateKey = decodeBase64PrivateKey(modulus, exponent, d, p, q, dP, dQ, qInv);

  // RSAES-OAEP Encryption Example 5.1
  message = 'r3GpAeOmHTEy8Pwf20dPnqZXklf/wk0WQXAUWz296A==';
  seed = 'RMkuKD93uUmcYD2WNmDIfS+TlGE=';
  encrypted = 'A2BGpKR9ntO6mokTnBBQOOt0krBaXWi/1TrM/0WX96aGUbR7SkYn2Sfkhe7XtFZkIOi0CYeeXWBuriUdIqXfeZ95IL/BF7mSVypTsSYxRrzqAzhcxehTyaEByMPhvaMaUZgHSWxsteXvtAiCOjUrj6BmH7Zk763Vk965n/9e0ADl';
  checkOAEPEncrypt(pubkey, privateKey, message, seed, encrypted);

  // RSAES-OAEP Encryption Example 5.2
  message = 'o7hEoII5qKxBYFrxemz9pNNQE2WFkDpBenkmh2BRmktKwzA+xz8Ph8+zI5k=';
  seed = 'yyj1hgZZ/O7knD7q/OYlpwgDvTI=';
  encrypted = 'A9brZU7c5hW8WfRVJl7U5aGCI8u5vk5AabRzgE1d6W9U3KqmA9BJxdlKoUcN/NIlQGa3x7Yf8fb2dw4yFcUTmf1ONOxQgrxI8ImECtBDVK5m3A8b0Y5GGjPMEli0Q6KDem3yZ1mqIwIzSYb4c4DJzJ1Tvp+ZYF0smpfaewkVpKet';
  checkOAEPEncrypt(pubkey, privateKey, message, seed, encrypted);

  // RSAES-OAEP Encryption Example 5.3
  message = 'MIsOy9LHbLd/xvcMXt0jP9LyCSnWKfAmlTu2Ko9KOjFL3hld6FtfgW2iqrB00my2rN3zI647nGeKw88S+93n';
  seed = 'IoX0DXcEgvmp76LHLLOsVXFtwMo=';
  encrypted = 'B3CVIYFkn5+fB/9ib/OiLDXEYkQ9kF1Fap/Qv/Q8rCynqfVU6UeLmsw6yDiwIED/0+GEfeLkJTkp+d2e5ARDJamwXKu4CLLuhA004V0QWj8feydpWhoHotc/4I7KqjycnU1aif+JDVRyfXrkDA7BqN2GFl2O4sY2gUEBaki1W2ln';
  checkOAEPEncrypt(pubkey, privateKey, message, seed, encrypted);

  // RSAES-OAEP Encryption Example 5.4
  message = 'FcW57hGF';
  seed = 'SfpF06eN0Q39V3OZ0esAr37tVRM=';
  encrypted = 'CBK3Z2jry2QtBAJY5fREGgGFIb2WaH5sXomfzWwXWI/1moLMiuA6S0WzEpmvF4jDKffc0oX4z0ztgmBrl2EmcaRb7coTNEIUTRYX0RT4AoV/D51zl1HFej+e5ACRLGHi5pkr4DGkPdSPproU7vfEIrXtxOevoE/dOPQC0ci7cZq/';
  checkOAEPEncrypt(pubkey, privateKey, message, seed, encrypted);

  // RSAES-OAEP Encryption Example 5.5
  message = 'IQJuaADH+nKPyqug0ZauKNeirE/9irznlPCYX2DIpnNydzZdP+oR24kjogKa';
  seed = '8Ch0EyNMxQNHJKCUxFhrh6/xM/w=';
  encrypted = 'B7YOFOyVS/0p5g0AR+eJ9R1XGGxjWJkDMGeTztP2gkHHQ1KaumpjdPkuGeAWPvozaX4Zb3Zh36qkeqxr3l5R3rUHxyxYmiyhaT2WsUYDgSSbLNuerER2nySJxdPS+Z8O48fuW/ZKWsecQr1DPxSb6MtZVINhZAWVUTyXr3vCUJcj';
  checkOAEPEncrypt(pubkey, privateKey, message, seed, encrypted);

  // RSAES-OAEP Encryption Example 5.6
  message = 'VB43totsiHK4TAI=';
  seed = '2fukXJbyHm4m0p6yzctlhb6cs0E=';
  encrypted = 'CMNtTdozQjsu1oMNhfZBG6Hc9HCh+uDr7+58CJ8lbO90y5bqacOPYPOavuRBKby0yS3n95diOyAHTj2cKJlwHtkHHh76C92E1MPlEwMC2PAkC6ukuEpxzAMvIjWl/w+uJ3w+j5ESvvRMmuINF1/JpAWL/JMLoxsC4uT0REg3EPJK';
  checkOAEPEncrypt(pubkey, privateKey, message, seed, encrypted);

  // Example 6: A 1029-bit RSA Key Pair
  // Components of the RSA Key Pair
  modulus = 'ErF/ba0uzRn/RtwT94YPCeDgz7Z3s4pSWSMFzq8CLBZtuQ0ErCnjP33RLZ+vZuCBa7Y+rSZ8x9RsF8N74hS8oqItcjpk5EQHQ2tvyWVymu/CVU83bNXc6mgpN4CmK/OdAClIWhYLu55dwJctIaUE9S5e4CiqQWMy9RCy6c/19yKv';
  exponent = 'AQAB';
  d = 'ApXso1YGGDaVWc7NMDqpz9r8HZ8GlZ33X/75KaqJaWG80ZDcaZftp/WWPnJNB7TcEfMGXlrpfZaDURIoC5CEuxTyoh69ToidQbnEEy7BlW/KuLsv7QV1iEk2Uixf99MyYZBIJOfK3uTguzctJFfPeOK9EoYij/g/EHMc5jyQz/P5';
  p = 'BKbOi3NY36ab3PdCYXAFr7U4X186WKJO90oiqMBct8w469TMnZqdeJpizQ9g8MuUHTQjyWku+k/jrf8pDEdJo4s=';
  q = 'BATJqAM3H+20xb4588ALAJ5eCKY74eQANc2spQEcxwHPfuvLmfD/4Xz9Ckv3vv0t1TaslG23l/28Sr6PKTSbke0=';
  dP = 'A5Ycj3YKor1RVMeq/XciWzus0BOa57WUjqMxH8zYb7lcda+nZyhLmy3lWVcvFdjQRMfrg6G+X63yzDd8DYR1KUs=';
  dQ = 'AiGX4GZ0IZaqvAP6L+605wsVy3h9YXrNMbt1x7wjStcG98SNIYLR8P+cIo3PQZZ7bAum0sCtEQobhXgx7CReLLE=';
  qInv = 'BAHEwMU9RdvbXp2W0P7PQnXfCXS8Sgc2tKdMMmkFPvtoas4kBuIsngWN20rlQGJ64v2wgmHo5+S8vJlNqvowXEU=';
  pubkey = decodeBase64PublicKey(modulus, exponent);
  privateKey = decodeBase64PrivateKey(modulus, exponent, d, p, q, dP, dQ, qInv);

  // RSAES-OAEP Encryption Example 6.1
  message = 'QEbKi6ozR8on9J4NgfnMHXG+m6UX1A==';
  seed = '3Q9s/kFeiOWkaaUfu6bf1ArbQ4Q=';
  encrypted = 'BjDuvNKFbCT3mIBuQfnmc0Xtqc7aOGrMn6yuoe7tBqzlg3CXGNnRafrfQU1cdvkploM+8wW3Wx5LlfZiog+u3DuuDEgnqL+KiO29V+wgOieoQfAuQ6YVurGoysBwHeNN6972KgiAibVew26nUi/T7I0GtqBz5t+DMVO8Cu/ZO9Gj';
  checkOAEPEncrypt(pubkey, privateKey, message, seed, encrypted);

  // RSAES-OAEP Encryption Example 6.2
  message = 'XMcsYCMd8Ds9QPm1eTG8MRCflyUn8osZ50gMcojLPJKyJRIhTkvmyRR5Ldq99X+qiqc=';
  seed = 'jRS9lGoTURSPXK4u2aDGU+hevYU=';
  encrypted = 'Drw3N2FzpP0vicxVwspismsR1Rw8fOSeiEX3TnYHMXxDa8jSO5Zn3+udCHI0tHvGg3F1rlwFWfa4HX0iQW0+UPSsUz2PCBLy2555H+nHdayLatD1Na2c6yOkoCAUxYqz+NMWFJmiYPOTSOcUriodNEMgj9i3Isz9+zk+mAEfmeY/';
  checkOAEPEncrypt(pubkey, privateKey, message, seed, encrypted);

  // RSAES-OAEP Encryption Example 6.3
  message = 'sg5lEwMJL0vMtDBwwPhtIwSTYu2WZC/FYywn20pS49gx8qsGiyOxSYecAC9r8/7ul1kRElYs';
  seed = 'bAdbxFUg8WXAv16kxd8ZG8nvDkQ=';
  encrypted = 'Cpi/EJNhk5RDbPaNjzji8Vj96OpU80NfI5uNBrgyGEQgJHau7ZYAlJJIDOOo1wVJjEyMaPAVAdyB22CPYAhzUMjDsL0unvaoFFi3yAG4ny5P6Z1JALpqS15althl3Gdsd1WSh5QTDWKAqBYKGQ8t8+p8+aoCcdiOnmkF7PHFFS1l';
  checkOAEPEncrypt(pubkey, privateKey, message, seed, encrypted);

  // RSAES-OAEP Encryption Example 6.4
  message = 'aE4wOMXAQfc=';
  seed = 'O7w71mN9/hKEaQECm/WwwHEDQ5w=';
  encrypted = 'AI56Z8rPtcTiS+x97hSRF/GVmM6MRYCP74jGCP+c1uaVJjuaPArUuLpMlSOOlqhCK4U1YpyNU4I3RHmtE/o5l0skL5p1nur5yDrVqMoYlAoBYrp1WHbfJj9L1QxlJcVgkCZ8Hw4JzgiZoM81nogSCr2b+JNEWzyud9Ngc1mumlL4';
  checkOAEPEncrypt(pubkey, privateKey, message, seed, encrypted);

  // RSAES-OAEP Encryption Example 6.5
  message = 'MkiMsmLQQdbk3TX5h788ppbbHwasKaRGkw==';
  seed = 'tGtBiT6L7zJvZ1k4OoMHHa5/yrw=';
  encrypted = 'AAA0dEFse2i9+WHDhXN5RNfx9AyzlTQ8aTzAtP5jsx/t8erurJzMBnizHcMuCXdIlRTE8JCF9imKllPwGupARf9YLuiHviauV1tz7vfzd0kh43Wj0ZrdoMoxqhhJiHwfQsrJZ396L06SP25ahos4wITvGHWU3J9/BI/qLgKVU4Sr';
  checkOAEPEncrypt(pubkey, privateKey, message, seed, encrypted);

  // RSAES-OAEP Encryption Example 6.6
  message = 'ULoUvoRicgJ5wwa6';
  seed = 'CiQDMSpB49UvBg+8E6Z95c92Cac=';
  encrypted = 'CgJt2l/IeF972b91Mntj6F4sD97l2ttl69ysmuHelcksZyq0M6p6jmnOam2Il/rErEpU3oQa5eW7znaHh515Y0zqejBoQGXHFNUkCbkoJWu/U+q81SMetyWVBFNzmb0pFktybTOkbacBNgpBaKCRzKty1Epi/tJGwP/qWxNIq1Rw';
  checkOAEPEncrypt(pubkey, privateKey, message, seed, encrypted);

  // Example 7: A 1030-bit RSA Key Pair
  // Components of the RSA Key Pair
  modulus = 'MRF58Lz8m508oxXQDvMNe906LPrpkRv+3LlIs6R4LQcytqtEqkvwN0GmRNwBvsPmmwGgM+Z12KzXxJJcaxrsMRkFHf2Jdi0hXUVHX/y1n5CBSGI/NxdxVvauht16fF9D3B4fkIJUBYooSl8GwAIXk6h/GsX+/33K7mnF5Ro3ieNz';
  exponent = 'AQAB';
  d = 'Bwz8/y/rgnbidDLEXf7kj0m3kX1lMOHwyjRg8y4CdhdEh8VuIqRdJQDXd1SVIZ19Flqc872Swyr5qY2NycwpaACtyUoKVPtA80KRv4TujqErbxCTWcbTVCpQ+cdn9c//BaaBwuZW+3fKqttL6UaNirzU35j1jobSBT+hNJ90jiGx';
  p = 'B0kmLBEc1HDsJWbms3MvwJMpRpqhkHHTucAZBlFMbx0muqFL6rCXHIt+YRpPeQCdb+p3aSjKJShbDeNkPRo/jHE=';
  q = 'BrweUOlsAr9jbp7qi4mbvr92Ud533UdMPpvCO62BgrYZBMfZffvr+x4AEIh4tuZ+QVOR1nlCwrK/m0Q1+IsMsCM=';
  dP = 'A7x+p/CqsUOrxs6LlxGGNqMBcuTP4CyPoN2jt7qvkPgJKYKYVSX0iL38tL1ybiJjmsZKMJKrf/y/HVM0z6ULW/E=';
  dQ = 'AmKmqinCo8Z9xTRsBjga/Zh6o8yTz7/s9U/dn514fX9ZpSPTmJedoTei9jgf6UgB98lNohUY3DTLQIcMRpeZStk=';
  qInv = 'ZJ1MF7buFyHnctA4mlWcPTzflVDUV8RrA3t0ZBsdUhZq+KITyDliBs37pEIvGNb2Hby10hTJcb9IKuuXanNwwg==';
  pubkey = decodeBase64PublicKey(modulus, exponent);
  privateKey = decodeBase64PrivateKey(modulus, exponent, d, p, q, dP, dQ, qInv);

  // RSAES-OAEP Encryption Example 7.1
  message = 'R6rpCQ==';
  seed = 'Q90JoH/0ysccqkYy7l4cHa7kzY8=';
  encrypted = 'FojkzneUu6bLcBQWns1VnO3iowtWpSto2f4Yzxlz75eyoDFTlRx1X2KUqkmtvbVYRatodfs5hsk+z5J5YoQNKC+eVM6LaQ98DLi71zRA2VcdGxbNkmD56rR4PMSC5SI9xglzhxeD7Cewrg/UdzLLwoahc/ySsA+0umgkZHzZPIXB';
  checkOAEPEncrypt(pubkey, privateKey, message, seed, encrypted);

  // RSAES-OAEP Encryption Example 7.2
  message = 'HZsuIiPZvBO/ufFiznNdtIunxo9oIqChp7auFlg05w==';
  seed = 'Opw87HuE+b063svGc+yZ1UsivJs=';
  encrypted = 'EFLtOXsuAeHQ7hxQvyQ2P5XlBPSgNDSgj9giV07WuXNu27XzkNsQMhR5qKE5NQ4r1Jd8N3jvMx8+eK4RiyaEUfIKLwHUcfXVPFZpNxcbLbwtS95FmleZ8DctZXQjmyMj0kXQu4HChrY8iaNhAXM35JAviKRn9MfyRL/Vq0ZDf/O2';
  checkOAEPEncrypt(pubkey, privateKey, message, seed, encrypted);

  // RSAES-OAEP Encryption Example 7.3
  message = '2Xb8';
  seed = 'dqdeW2FXpVbPiIS7LkXCk91UXPU=';
  encrypted = 'IVXNhD/ySk7outt2lCYAKKSQgTuos2mky/EG7BSOUphwf1llvn0QHBBJ6oWEwkzWNFWtnBBNaGKC0/uAOkwRwcLpuRxxeIAdG2ZA8AP1co3wB7ikzMkrzgXkGicnjXyFAYxSQUMTpQd3iQAdTwGRC3Kq0F0iCqFKWHM6dIm8VFVr';
  checkOAEPEncrypt(pubkey, privateKey, message, seed, encrypted);

  // RSAES-OAEP Encryption Example 7.4
  message = '1HOGI98iOqQ4Q9+EZ1NMQdAT4MgDxiTiY2ZrI5veQKXymuuN5549qmHdA3D0m9SwE4NLmCEq72scXuNzs8s=';
  seed = 'eGYxSmrW8rJQo1lB2yj1hktYWFk=';
  encrypted = 'CrFMNzrrfUMo0KqtjAlNiLnrCYuV8hBUopCCUivnwnoxKHi2N5F+PYGebDxWjbXYQ4ArBtUdnpiivgv0DAMUI7AO37/4Mg77kXG9IERlOky5xRIvbGXoPNouw8EmAnqcGla6h00P6iPzgLgs8kC4z1QABHWMTHfZNBV6dPP8Er+s';
  checkOAEPEncrypt(pubkey, privateKey, message, seed, encrypted);

  // RSAES-OAEP Encryption Example 7.5
  message = 'u0cjHKXqHTrUbJk0XZqKYQ==';
  seed = 'shZu1HLVjbEMqyxrAAzM8Qp9xQk=';
  encrypted = 'AoOHoxgndDR5i02X9GAGjfUpj6ulBBuhF2Ghy3MWskGEEU7FACV+JYntO2B6HrvpemzC4CvxtoH0IxKjO3p32OeFXEpt4D48BGQ/eGuRomSg1oBeLOqR5oF363pk2SVeTyfnE7fM7ADcIA69IcLqK7iQ/q5JQt+UHcP5eJDtNHR4';
  checkOAEPEncrypt(pubkey, privateKey, message, seed, encrypted);

  // RSAES-OAEP Encryption Example 7.6
  message = 'IYSCcJXTXD+G9gDo5ZdUATKW';
  seed = 'Umc73iyhZsKqRhMawdyAjWfX07E=';
  encrypted = 'FMZ4qUrWBSXvOelZsvO6XAl6lP+RK2fbrOgFNcGHq9R9B1QgsYchUrugj3/DHzE7v5JzyRL8TAFJqbDPt5gH40brMyBpYRvsD/m80Wjx98M+dzE86kVLlOJUnuzwAuKs9/by0oRdT+CqsuWpLd9oxICuESR5NdH2JXSEIhauZ0EV';
  checkOAEPEncrypt(pubkey, privateKey, message, seed, encrypted);

  // Example 8: A 1031-bit RSA Key Pair
  // Components of the RSA Key Pair
  modulus = 'W98OMNMh3aUUf4gkCPppGVSA34+A0/bov1gYUE82QnypsfVUC5xlqPaXTPhEeiRNkoAgG7Sfy75jeNGUTNIn4jD5bj0Q+Bnc7ydsZKALKktnAefQHeX6veOx6aDfgvRjE1nNImaWR/uxcXJGE07XtJfP/73EK1nHOpbtkBZiEt/3';
  exponent = 'AQAB';
  d = 'D30enlqqJf0T5KBmOuFE4NFfXNGLzbCd8sx+ZOPF6RWtYmRTBBYdCYxxW7eri9AdB+rz/tfH7QivKopi70SrFrMg4Ur3Kkj5av4mKgrkz2XmNekQeQzU7lzqdopLJjn35vZ3s/C7a+MrdXR9iQkDbwJk9Y1AHNuhMXFhV6dez2Mx';
  p = 'CgLvhEjZ+ti70NAEyMKql1HvlyHBsNAyNqVLDflHy67VolXuno4g1JHqFyP+CUcEqXYuiK/RbrtZlEEsqWbcT58=';
  q = 'CS02Ln7ToL/Z6f0ObAMBtt8pFZz1DMg7mwz01u6nGmHgArRuCuny3mLSW110UtSYuByaxvxYWT1MP7T11y37sKk=';
  dP = 'B8cUEK8QOWLbNnQE43roULqk6cKd2SFFgVKUpnx9HG3tJjqgMKm2M65QMD4UA10a8BQSPrpoeCAwjY68hbaVfX0=';
  dQ = 'rix1OAwCwBatBYkbMwHeiB8orhFxGCtrLIO+p8UV7KnKKYx7HKtYF6WXBo/IUGDeTaigFjeKrkPH+We8w3kEuQ==';
  qInv = 'BZjRBZ462k9jIHUsCdgF/30fGuDQF67u6c76DX3X/3deRLV4Mi9kBdYhHaGVGWZqqH/cTNjIj2tuPWfpYdy7o9A=';
  pubkey = decodeBase64PublicKey(modulus, exponent);
  privateKey = decodeBase64PrivateKey(modulus, exponent, d, p, q, dP, dQ, qInv);

  // RSAES-OAEP Encryption Example 8.1
  message = 'BQt1Xl5ogPe56daSp0w3quRJsxv+pt7/g3R6iX9sLIJbsa2/hQo8lplLXeWzPLx9SheROnln';
  seed = 'dwb/yh7PsevuKlXlxuJM0nl6QSU=';
  encrypted = 'CbNoPYousPspW2LtH7kpC3FEV7eCUxn0ZHhyr4ibMECUcgIK0SkSvxmxHUgZ9JYUgk/9hNCcChfn0XMJ0SkZeQQQqimVaZ9qhtvjJCtazCOvRWkQgNaxroEPs+MFcIfwlwCSzgC+lWL/QFO2Jizgyqk+E3I9LjpboHXUXw1htUth';
  checkOAEPEncrypt(pubkey, privateKey, message, seed, encrypted);

  // RSAES-OAEP Encryption Example 8.2
  message = 'TraNzZPKmxnfERvUNgj1VwJv5KodXPrCJ6PrWrlUjBigbd7SP4GCWYay/NcRCezvfv+Ihz8HXCqgxGn2nJK8';
  seed = 'o3F9oUO03P+8dCZlqPqVBYVUg0M=';
  encrypted = 'Ls8VyXxaFbFHaumGs3G1eiQoT0oWKo0MgYLnkF55IlbxgSul+D8fehMOQtzAIjKETtwUoxpo7peuVko4OjQRZWQkxfYt22Rgk8Nnvh/NpCbPAKBtist+V3dvu9hVrD31BvwWsdfD8hEPPYBo6R4YY2ODHIQJaA2NqezYzx+iDuOd';
  checkOAEPEncrypt(pubkey, privateKey, message, seed, encrypted);

  // RSAES-OAEP Encryption Example 8.3
  message = 'hgSsVjKMGrWtkXhh';
  seed = '7gYgkHPMoCa7Jk5Rhb+MaLdzn4Y=';
  encrypted = 'S8iRMKWy2rt8L8+Q610Or55oG3FGo48xc6PZz+xS6p4KQZMuZIqdaTRMUNp2P1GgPJV2ITHoBSJU3NIkjLpA/TFmd4bOBaK3tTGsnaye1YSlm2d8GortjF0V1owFVp4r54C/fbY4/Sv9KoWrJ2hg83dzOPypif/XQ9E+4I4MqYk/';
  checkOAEPEncrypt(pubkey, privateKey, message, seed, encrypted);

  // RSAES-OAEP Encryption Example 8.4
  message = '/dpfv27DYanZpKxoryFqBob0OLHg5cNrlV904QfznA3dzA==';
  seed = 'mQrVc9xIqXMjW22CVDYY8ulVEF0=';
  encrypted = 'LkVoR9j8Nv8BR9aZNZS5OXIn1Xd1LHnQ+QT8sDnU2BL+pgWntXTdgsp4b5N1I0hDjun1tUVJhdXw4WmePnrRdaMuFfA96wQquf4d2dsbuG+MCJzLRefvDF7nyptykMprFb7UcDl4ioqT/4Pg6NYkTHEAY2Le72m29Bb7PGhDg/vQ';
  checkOAEPEncrypt(pubkey, privateKey, message, seed, encrypted);

  // RSAES-OAEP Encryption Example 8.5
  message = 'Sl9JFL7iXePGk0HeBw==';
  seed = '7MY7KPB1byL1Ksjm7BJRpuwwRxg=';
  encrypted = 'H7k1b9XEsXltsuv30NOTzIEK32FF3vwvznFPedk4ANXirCEeqLvsyktlS5TDsYsw3Vds403JVDbvV6CUFWRZIzWaXXtBce8iwkZw8bIp02A+kfdmcbffl+cxfJdzRHbV89F9Ic+Ctbqfg98uWI02mE/RtYRGi9I7LodfMvaJU/ey';
  checkOAEPEncrypt(pubkey, privateKey, message, seed, encrypted);

  // RSAES-OAEP Encryption Example 8.6
  message = 'jgfWb3uICnJWOrzT81CSvDNAn7f4jyRyvg==';
  seed = 'OSXHGzYtQKCm3kIUVXm6Hn3UWfw=';
  encrypted = 'Ov2cZgAUeyF5jYGMZVoPTJIS2ybQsN/cKnWUzLPSL1vx18PhEs1z/H1QnHqLr908J00TmQCflgnsS+ZHfkU/B1qjPbOChwwcNAmu85LXOGrjppa5mpS02gWJRH6VXRbJixdgKlm9c2J5/Nj7KAxEYtWQv6m/E/7VcOr96XMwosIQ';
  checkOAEPEncrypt(pubkey, privateKey, message, seed, encrypted);

  // Example 9: A 1536-bit RSA Key Pair
  // Components of the RSA Key Pair
  modulus = 'zyzUHjTKOnKOpcuK/2TDbSe971Nk4zb9aNMSPFoZaowocBPoU9UVbVjRUZVFIPtPbXsXq7aBd2WQnFdhGWWdkCsZBu2KKxDBVcJNEkUo2rnurjeb6sZuSkEXhty4/QBi68Aw3hIZoEwqjBt90xMeTWtsruLjGl7UGsFQmy7x7iqxg2S+VoypQcJezIT/nWQ7XsGqrhAqINc/R5t4D9bakQdSEtnqwDoGdNiZ66LkMfTES2Fba6IjK9SzO67XPWJd';
  exponent = 'AQAB';
  d = 'GYwUHiNxWpK8z2oRmlvBE4lGjSgR9UjXJ+F7SrDrmG1vIR77U7cffMvqh+5px17mFQCMUzLetSvzkKvfv+N9cgU2gVmyY4wd4ybiHSIlHw+1hIs78VAF0qdDMPCv6RbuYszBNE0dg6cJ5gZ2JzhA9/N3QkpeCk2nXwGzH/doGc+cv90hUkPDkXwD7zgZkxLlZ7O/eu06tFfzce+KFCP0W2jG4oLsERu6KDO5h/1p+tg7wbjGE8Xh6hbBHtEl6n7B';
  p = '/I1sBL7E65qBksp5AMvlNuLotRnezzOyRZeYxpCd9PF2230jGQ/HK4hlpxiviV8bzZFFKYAnQjtgXnCkfPWDkKjD6I/IxI6LMuPaIQ374+iB6lZ0tqNIwh6T+eVepl79';
  q = '0gDUXniKrOpgakAdBGD4fdXBAn4S3BoNdYbok52c94m0D1GsBEKWHefSHMIeBcgxVcHyqpGTOHz9+VbLSNFTuicEBvm7ulN9SYfZ4vmULXoUy//+p0/s3ako0j4ln17h';
  dP = '2xaAL3mi8NRfNY1p/TPkS4H66ChiLpOlQlPpl9AbB0N1naDoErSqTmyL6rIyjVQxlVpBimf/JqjFyAel2jVOBe8xzIz3WPRjcylQsD4mVyb7lOOdalcqJiRKsI23V1Kt';
  dQ = 'oKMXz+ffFCP4em3uhFH04rSmflSX8ptPHk6DC5+t2UARZwJvVZblo5yXgX4PXxbifhnsmQLgHX6m+5qjx2Cv7h44G2neasnAdYWgatnEugC/dcitL6iYpHnoCuKU/tKh';
  qInv = 'CyHzNcNTNC60TDqiREV4DC1lW5QBdMrjjHyKTmSTwLqf0wN0gmewg7mnpsth5C2zYrjJiW23Bk4CrVrmFYfaFbRknJBZSQn+s328tlS+tyaOyAHlqLSqORG+vYhULwW+';
  pubkey = decodeBase64PublicKey(modulus, exponent);
  privateKey = decodeBase64PrivateKey(modulus, exponent, d, p, q, dP, dQ, qInv);

  // RSAES-OAEP Encryption Example 9.1
  message = '9zX9VbqSWSw7Urj5xPaaqhy++P6IrdCVWVQSRn+c9OwLiWxZ7aFiEOdUnIq7EM28IaEuyba1uP0vEDmetg==';
  seed = 'jsll8TSj7Jkx6SocoNyBadXqcFw=';
  encrypted = 'JnvNEYrKsfyLqByF1zADy4YQ+lXB2X2o1Ip8fwaJak23UaooQlW502rWXzdlPYKfGzf5e4ABlCVFsvwsVac3bKehvksXYMjgWjPlqiUmuNmOMXCI54NMdVsqWbEmMaGCwF1dQ6sXeSZPhFb1Fc5X399RLVST2re3M43Et9eNucCRrDuvU3pp/H9UnZefDv+alP2kFpvU0dGaacmeM8O1VJDVAbObHtrhGP9nk6FTJhWE06Xzn25oLj0XyM0SYfpy';
  checkOAEPEncrypt(pubkey, privateKey, message, seed, encrypted);

  // RSAES-OAEP Encryption Example 9.2
  message = 'gbkGYFAVpjqr5C3fEeGXiRL1QEx0dLJtzj7Ugr+WHsyBi/QgxUZZ';
  seed = '7LG4sl+lDNqwjlYEKGf0r1gm0Ww=';
  encrypted = 'k6yfBnHsKay7RE7/waV0E1HWD9sOOT+/dUrPDeSXYaFIQd93cum8gnc5ZqFYTE1yuuoAEY+D81zKblN8vU2BH1WDspeD2KbZTNMb5w1vUmwQ/wnG+nzgaXlaP80FEf1fy1ZLzIDqnHjzi4ABJTnYpN32/oHpzdt/UNu7vMfl2GCXzPTsSRifuL8xi+bVoHFdUWtJrxkSWM0y3IM85utGc8A6Gbus6IzFSJX2NswMHsiQltEc4jWiZcoXZCMqaJro';
  checkOAEPEncrypt(pubkey, privateKey, message, seed, encrypted);

  // RSAES-OAEP Encryption Example 9.3
  message = '/TJkKd+biQ4JtUsYuPNPHiQ=';
  seed = '6JuwMsbOYiy9tTvJRmAU6nf3d8A=';
  encrypted = 'gevdlQVLDIIu+a12k/Woet+0tMTOcN8t+E7UnATaWLpfwgoZ4abot6OQCyJ5bcToae5rQnktFajs61bAnGmRToE86o9pMeS47W9CGvKY1ZXJf0eJx8qmEsfvNgmEwhuT7cVAEGi1r0x4qHcbmE1TuOqK3y9qfUoLp2x14d2fZY8g3tSkYHHUbXeRtWgD2P6n8LD45Brj8JODpvlYX+d1Pqr/0r+UVjEIvuzCB7u1NfX8xwXw3en3CMYvSanJA3HT';
  checkOAEPEncrypt(pubkey, privateKey, message, seed, encrypted);

  // RSAES-OAEP Encryption Example 9.4
  message = '8UWbXwyS8BoPcjouVmJITY+MCiD8KdrWrNQ7tfPv/fThtj4H/f5mKNDXTKGb8taeSgq/htKTklp5Z3L4CI4=';
  seed = 'YG87mcC5zNdx6qKeoOTIhPMYnMw=';
  encrypted = 'vMNflM3mbLETZiXWJblEMqNbIvPS+hGmE/8PylvVf4e5AszcHNCuvLBxXuhp0dH+OV9nkwA/XspGUFnIhmDURv9fCBhVICJVfjjAimfq2ZEmIlTxBoKXXsVjl3aFN/SXevbV9qrOt/sl3sWTcjAjH9iXivSRGaKfKeQkq4JytHVieS1clPd0uIKdCw2fGoye3fN1dNX6JI7vqcUnH8XsJXnIG91htBD6Yf425CQiHBE63bJ1ZkyAHTTKjGNR5KhY';
  checkOAEPEncrypt(pubkey, privateKey, message, seed, encrypted);

  // RSAES-OAEP Encryption Example 9.5
  message = 'U+boxynW+cMZ3TF+dLDbjkzMol88gwV0bhN6xjpj7zc557WVq7lujVXlT3vUGrQzN4/7kR0=';
  seed = '/LxCFALp7KvGCCr6QLpfJlIshA4=';
  encrypted = 'Iyr7ySf6CML2onuH1KXLCcB9wm+uc9c6kFWIOfT9ZtKBuH7HNLziN7oWZpjtgpEGp95pQs1s3OeP7Y0uTYFCjmZJDQNiZM75KvlB0+NQVf45geFNKcu5pPZ0cwY7rseaEXn1oXycGDLyg4/X1eWbuWWdVtzooBnt7xuzrMxpfMbMenePYKBkx/b11SnGIQJi4APeWD6B4xZ7iZcfuMDhXUT//vibU9jWTdeX0Vm1bSsI6lMH6hLCQb1Y1O4nih8u';
  checkOAEPEncrypt(pubkey, privateKey, message, seed, encrypted);

  // RSAES-OAEP Encryption Example 9.6
  message = 'trKOohmNDBAIvGQ=';
  seed = 'I6reDh4Iu5uaeNIwKlL5whsuG6I=';
  encrypted = 'Q4zH3AimjaJJ5CUF+Fc7pg4sJ3PVspD0z53/cY6EIIHDg+ZwJKDylZTqmHudJeS3OPKFlw0ZWrs6jIBU49eda5yagye6WW8SWeJxJmdHZpB9jVgv86hHYVSSmtsebRI1ssy07I9mO6nMZwqSvr2FPI2/acZDbQFvYa3YNulHMkUENCB/n9TEPewqEqlY76Ae/iZpiZteYEwlXFX7cWbeVYnjaVl7sJFowG3V2xd+BqF0DrLVyC+uym2S/O6ZMbqf';
  checkOAEPEncrypt(pubkey, privateKey, message, seed, encrypted);

  // Example 10: A 2048-bit RSA Key Pair
  // Components of the RSA Key Pair
  modulus = 'rkXtVgHOxrjMBfgDk1xnTdvg11xMCf15UfxrDK7DE6jfOZcMUYv/ul7Wjz8NfyKkAp1BPxrgfk6+nkF3ziPn9UBLVp5O4b3PPB+wPvETgC1PhV65tRNLWnyAha3K5vovoUF+w3Y74XGwxit2Dt4jwSrZK5gIhMZB9aj6wmva1KAzgaIv4bdUiFCUyCUG1AGaU1ooav6ycbubpZLeGNz2AMKu6uVuAvfPefwUzzvcfNhP67v5UMqQMEsiGaeqBjrvosPBmA5WDNZK/neVhbYQdle5V4V+/eYBCYirfeQX/IjY84TE5ucsP5Q+DDHAxKXMNvh52KOsnX1Zhg6q2muDuw==';
  exponent = 'AQAB';
  d = 'BWsEIW/l81SsdyUKS2sMhSWoXFmwvYDFZFCiLV9DjllqMzqodeKR3UP0jLiLnV/A1Jn5/NHDl/mvwHDNnjmMjRnmHbfHQQprJnXfv100W4BNIBrdUC1c4t/LCRzpmXu+vlcwbzg+TViBA/A29+hdGTTRUqMj5KjbRR1vSlsbDxAswVDgL+7iuI3qStTBusyyTYQHLRTh0kpncfdAjuMFZPuG1Dk6NLzwt4hQHRkzA/E6IoSwAfD2Ser3kyjUrFxDCrRBSSCpRg7Rt7xA7GU+h20Jq8UJrkW1JRkBFqDCYQGEgphQnBw786SD5ydAVOFelwdQNumJ9gkygHtSV3UeeQ==';
  p = '7PWuzR5VFf/6y9daKBbG6/SQGM37RjjhhdZqc5a2+AkPgBjH/ZXMNLhX3BfwzGUWuxNGq01YLK2te0EDNSOHtwM40IQEfJ2VObZJYgSz3W6kQkmSB77AH5ZCh/9jNsOYRlgzaEb1bkaGGIHBAjPSF2vxWl6W3ceAvIaKp30852k=';
  q = 'vEbEZPxqxMp4Ow6wijyEG3cvfpsvKLq9WIroheGgxh5IWKD7JawpmZDzW+hRZMJZuhF1zdcZJwcTUYSZK2wpt0bdDSyr4UKDX30UjMFhUktKCZRtSLgoRz8c52tstohsNFwD4F9B1RtcOpCj8kBzx9dKT+JdnPIcdZYPP8OGMYM=';
  dP = 'xzVkVx0A+xXQij3plXpQkV1xJulELaz0K8guhi5Wc/9qAI7U0uN0YX34nxehYLQ7f9qctra3QhhgmBX31FyiY8FZqjLSctEn+vS8jKLXc3jorrGbCtfaPLPeCucxSYD2K21LCoddHfA8G645zNgz72zX4tlSi/CE0flp55Tp9sE=';
  dQ = 'Jlizf235wQML4dtoEX+p2H456itpO35tOi9wlHQT7sYULhj7jfy2rFRdfIagrUj4RXFw8O+ya8SBJsU+/R0WkgGY3CoRB9woLbaoDNMGI2C6P6E/cOQxL/GmzWuPxM2cXD2xfG1qVyEvc64p9hkye61ZsVOFhYW6Tii2CmKkXkk=';
  qInv = 'bzhSazklCFU07z5BWoNu3ouGFYosfL/sywvYNDBP7Gg7qNT0ecQz1DQW5jJpYjzqEAd22Fr/QB0//2EO5lQRzjsTY9Y6lwnu3kJkfOpWFJPVRXCoecGGgs2XcQuWIF7DERfXO182Ij+t1ui6kN18DuYdROFjJR4gx/ZuswURfLg=';
  pubkey = decodeBase64PublicKey(modulus, exponent);
  privateKey = decodeBase64PrivateKey(modulus, exponent, d, p, q, dP, dQ, qInv);

  // RSAES-OAEP Encryption Example 10.1
  message = 'i7pr+CpsD4bV8XVul5VocLCJU7BrTrIFvBaU7g==';
  seed = 'R+GrcRn+5WyV7l6q2G9A0KpjvTM=';
  encrypted = 'U+pdwIzSYPs7hYVnKH+pFVLDCy/r+6IT8K6HcC0GjRm6sH/ldFI9+0ITnWjDxa/u4L/ky3lpy/OCuATW5hOWFE4tDmB0H4mTwwFLWLmxlXqLq80jr4VPTDVvsWYqpyv8x+WGVZ3EKA0WDBJnhacj6+6+/3HxFZRECq74fRB5Ood0ojnUoEyH/hRnudr4UgjsbHJVeUqWzCkUL5qL1Bjjwf1nNEsM0IKd87K+xgJTGWKTxrNNP3XTLyE91Fxic9UFrfTM7RBXy3WPwmru+kQSVe1OZMGZ7gdefxZkYYL9tGRzm2irXa/w5j6VUgFoJPBUv008jJCpe7a2VTKE60KfzA==';
  checkOAEPEncrypt(pubkey, privateKey, message, seed, encrypted);

  // RSAES-OAEP Encryption Example 10.2
  message = '5q0YHwU7WKkE8kV1EDc+Vw==';
  seed = 'bRf1tMH/rDUdGVv3sJ0J8JpAec8=';
  encrypted = 'orGkMKnWV+L6HCu17UP/slwFowj+kJPAEDF5X1h0QAEQgorlj7m1gc6d3dPlSa4EoJhUWb3mxiZZTnsF3EJ4sqFGXBNoQIgjyF6W3GbDowmDxjlmT8RWmjf+IeWhlbV3bu0t+NjTYa9obnUCKbvWY/FhhopQYV4MM3vsDKNf7AuxnDbrLgu8wFgvodk6rNsGEGP1nyzh7kNgXl2J7KGD0qzf6fgQEQIq07Q6PdQX2slLThHqgbGSlm6WaxgggucZZGB7T4AC82KZhEoR8q4PrqwurnD49PmAiKzc0KxVbp/MxRFSGQj60m8ExkIBRQMFd4dYsFOL+LW7FEqCjmKXlQ==';
  checkOAEPEncrypt(pubkey, privateKey, message, seed, encrypted);

  // RSAES-OAEP Encryption Example 10.3
  message = 'UQos9g6Gb6I0BVPJTqOfvCVjEeg+lEVLQSQ=';
  seed = 'OFOHUU3szHx0DdjN+druSaHL/VQ=';
  encrypted = 'mIbD5nZKi5qE6EFI69jDsaqAUDgaePZocUwW2c/Spu3FaXnFNdne47RLhcGL6JKJkjcXEUciFtld2pjS7oNHybFN/9/4SqSNJawG99fmU5islnsc6Qkl9n3OBJt/gS2wdCmXp01E/oHb4Oej/q8uXECviI1VDdu+O8IGV6KVQ/j8KRO5vRphsqsiVuxAm719wNF3F+olxD9C7Sffhzi/SvxnZv96/whZVV7ig5IPTIpjxKc0DLr93DOezbSwUVAC+WyTK1t5Fnr2mcCtP8z98PROhacCYr8uGP40uFBYmXXoZ/+WnUjqvyEicVRs3AWmnstSblKHDINvMHvXmHgO3g==';
  checkOAEPEncrypt(pubkey, privateKey, message, seed, encrypted);

  // RSAES-OAEP Encryption Example 10.4
  message = 'vN0ZDaO30wDfmgbiLKrip18QyR/2Z7fBa96LUwZKJkmpQEXJ';
  seed = 'XKymoPdkFhqWhPhdkrbg7zfKi2U=';
  encrypted = 'Yxjp+1wNBeUwfhaDQ26QMpOsRkI1iqoiPXFjATq6h+Lf2o5gxoYOKaHpJoYWPqC5F18ynKOxMaHt06d3Wai5e61qT49DlvKM9vOcpYES5IFg1uID2qWFbzrKX/7Vd69JlAjj39Iz4+YE2+NKnEyQgt5lUnysYzHSncgOBQig+nEi5/Mp9sylz6NNTR2kF4BUV+AIvsVJ5Hj/nhKnY8R30Vu7ePW2m9V4MPwsTtaG15vHKpXYX4gTTGsK/laozPvIVYKLszm9F5Cc8dcN4zNa4HA5CT5gbWVTZd5lULhyzW3h1EDuAxthlF9imtijU7DUCTnpajxFDSqNXu6fZ4CTyA==';
  checkOAEPEncrypt(pubkey, privateKey, message, seed, encrypted);

  // RSAES-OAEP Encryption Example 10.5
  message = 'p91sfcJLRvndXx6RraTDs9+UfodyMqk=';
  seed = 'lbyp44WYlLPdhp+n7NW7xkAb8+Q=';
  encrypted = 'dSkIcsz9SkUFZg1lH1babaoJyhMB2JBjL2qZLz1WXO5GSv3tQO07W+k1ZxTqWqdlX0oTZsLxfHKPbyxaXR+OKEKbxOb48s/42o3A4KmAjkX9CeovpAyyts5v//XA4VnRG2jZCoX3uE4QOwnmgmZkgMZXUFwJKSWUaKMUeG106rExVzzyNL9X232eZsxnSBkuAC3A3uqTBYXwgx/c2bwz1R957S/8Frz01ZgS/OvKo/kGmw5EVobWRMJcz2O0Vu5fpv/pbxnN91H+2erzWVd1Tb9L/qUhaqGETcUHyy0IDnIuuhUDCMK1/xGTYg8XZuz0SBuvuUO9KSh38hNspJSroA==';
  checkOAEPEncrypt(pubkey, privateKey, message, seed, encrypted);

  // RSAES-OAEP Encryption Example 10.6
  message = '6vGnOhsMRglTfeac2SKLvPuajKjGw++vBW/kp/RjTtALfDnsaSLXuOosBOus';
  seed = 'n0fd9C6X7qhWqb28cU6zrCL26zI=';
  encrypted = 'LSB6c0Mqj7TAMFGz9zsophdkCY36NMR6IJlfgRWqaBZnm1V+gtvuWEkIxuaXgtfes029Za8GPVf8p2pf0GlJL9YGjZmE0gk1BWWmLlx38jA4wSyxDGY0cJtUfEb2tKcJvYXKEi10Rl75d2LCl2Pgbbx6nnOMeL/KAQLcXnnWW5c/KCQMqrLhYaeLV9JiRX7YGV1T48eunaAhiDxtt8JK/dIyLqyXKtPDVMX87x4UbDoCkPtnrfAHBm4AQo0s7BjOWPkyhpje/vSy617HaRj94cGYy7OLevxnYmqa7+xDIr/ZDSVjSByaIh94yCcsgtG2KrkU4cafavbvMMpSYNtKRg==';
  checkOAEPEncrypt(pubkey, privateKey, message, seed, encrypted);
}

var tests = [testCorruptDecrypt, testZeroMessage, testOAEP];
for (var i = 0; i < tests.length; i++) {
  process.stdout.write('.');
  tests[i]();
}
console.log('SUCCESS');
