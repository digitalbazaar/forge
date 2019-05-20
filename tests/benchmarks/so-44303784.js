// https://stackoverflow.com/questions/44303784/javascript-aes-encryption-is-slow

// Test decryption with single update(), many update()s, and node
// Test chunk size for many update()s

const forge = require('../..');
const assert = require('assert');
const crypto = require('crypto');

const pwd = 'aStringPassword';
const iv = forge.random.getBytesSync(16);
const salt = forge.random.getBytesSync(16);
const key = forge.pkcs5.pbkdf2(pwd, salt, 100, 16);

function test_forge(bytes) {
  const buf = forge.util.createBuffer(bytes);
  const start = new Date();

  const decipher = forge.cipher.createDecipher('AES-CBC', key);
  decipher.start({iv: iv});
  decipher.update(buf);
  const result = decipher.finish();
  assert(result);
  const plain = decipher.output.getBytes();

  const time = (new Date() - start) / 1000;
  //console.log(`decrypted in ${time}s`);

  return {
    time,
    plain
  };
}

function test_forge_chunk(bytes, chunkSize) {
  if(!chunkSize) {
    chunkSize = 1024 * 16;
  }
  const start = new Date();

  const decipher = forge.cipher.createDecipher('AES-CBC', key);
  decipher.start({iv: iv});
  const length = bytes.length;
  let index = 0;
  let plain = '';
  do {
    plain += decipher.output.getBytes();
    const buf = forge.util.createBuffer(bytes.substr(index, chunkSize));
    decipher.update(buf);
    index += chunkSize;
  } while(index < length);
  const result = decipher.finish();
  assert(result);
  plain += decipher.output.getBytes();

  const time = (new Date() - start) / 1000;
  //console.log(`decrypted in ${time}s`);

  return {
    time,
    plain
  };
}

function test_node(bytes) {
  const bufb = Buffer.from(bytes, 'binary');
  const ivb = Buffer.from(iv, 'binary');
  const keyb = Buffer.from(key, 'binary');

  const start = new Date();

  const decipher = crypto.createDecipheriv('aes-128-cbc', keyb, ivb);

  let plain = decipher.update(bufb, 'utf8', 'utf8');
  plain += decipher.final('utf8');

  const time = (new Date() - start) / 1000;
  //console.log(`decrypted in ${time}s`);

  return {
    time,
    plain
  };
}

function data(megs) {
  // slower single chunk
  const start = new Date();
  var x = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';
  var plain = '';
  const minlen = megs * 1024 * 1024;
  while(plain.length < minlen) {
    plain += x;
  }
  const cipher = forge.cipher.createCipher('AES-CBC', key);
  cipher.start({iv: iv});
  cipher.update(forge.util.createBuffer(plain));
  const result = cipher.finish();
  assert(result);
  const encrypted = cipher.output.getBytes();

  const time = (new Date() - start) / 1000;
  //console.log(`data m:${megs} t:${time}s m/s:${megs/time}`);

  return {
    plain,
    encrypted,
    time
  };
}

function data_chunk(megs, chunkSize) {
  if(!chunkSize) {
    chunkSize = 1024 * 16;
  }

  // faster with chunksize
  const start = new Date();
  // make some large plain text bigger than some size
  var x = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';
  var plain = '';
  const minlen = megs * 1024 * 1024;
  while(plain.length < minlen) {
    plain += x;
  }

  const cipher = forge.cipher.createCipher('AES-CBC', key);
  cipher.start({iv: iv});
  const length = plain.length;
  let index = 0;
  let encrypted = '';
  do {
    encrypted += cipher.output.getBytes();
    const buf = forge.util.createBuffer(plain.substr(index, chunkSize));
    cipher.update(buf);
    index += chunkSize;
  } while(index < length);
  const result = cipher.finish();
  assert(result);
  encrypted += cipher.output.getBytes();

  const time = (new Date() - start) / 1000;
  //console.log(`data_chunk m:${megs} t:${time}s m/s:${megs/time}`);

  return {
    plain,
    encrypted,
    time
  };
}

function compareImpl() {
  const maxmegs = 20;
  let csv = '';
  // sweep input size
  for(let i = 1; i <= maxmegs; ++i) {
    //const input = data(i);
    const input = data_chunk(i, 1024 * 64);

    // forge w/ one chunk
    const tfs = [
      test_forge(input.encrypted),
      test_forge(input.encrypted),
      test_forge(input.encrypted)
    ];
    tfs.forEach(res => assert(input.plain == res.plain));
    const tf = tfs.reduce((prev, cur) => prev.time < cur.time ? prev : cur);

    // forge w/ chunks
    const chunkSize = 1024 * 64;
    const tfcs = [
      test_forge_chunk(input.encrypted, chunkSize),
      test_forge_chunk(input.encrypted, chunkSize),
      test_forge_chunk(input.encrypted, chunkSize)
    ];
    tfcs.forEach(res => assert(input.plain == res.plain));
    const tfc = tfcs.reduce((prev, cur) => prev.time < cur.time ? prev : cur);

    // node
    const tns = [
      test_node(input.encrypted),
      test_node(input.encrypted),
      test_node(input.encrypted)
    ];
    tns.forEach(res => assert(input.plain == res.plain));
    const tn = tns.reduce((prev, cur) => prev.time < cur.time ? prev : cur);

    /* eslint-disable max-len */
    csv += `${i}\t${tf.time}\t${i / tf.time}\t${tfc.time}\t${i / tfc.time}\t${tn.time}\t${i / tn.time}\t${tf.time / tn.time}\t${tfc.time / tn.time}\n`;
    console.log(`m:${i} tf:${tf.time} tf/s:${i / tf.time} tfc:${tfc.time} tfc/s:${i / tfc.time} tn:${tn.time} tn/s:${i / tn.time} sf:${tf.time / tn.time} sfc:${tfc.time / tn.time}`);
    /* eslint-enable max-len */
  }
  console.log(csv);
}

function compareDecChunkSize() {
  const megs = 10;
  let csv = '';
  const input = data_chunk(megs, 1024 * 64);
  function _test(k) {
    const chunkSize = 1024 * k;
    const tfcs = [
      test_forge_chunk(input.encrypted, chunkSize),
      test_forge_chunk(input.encrypted, chunkSize),
      test_forge_chunk(input.encrypted, chunkSize)
    ];
    tfcs.forEach(res => assert(input.plain == res.plain));
    const tfc = tfcs.reduce((prev, cur) => prev.time < cur.time ? prev : cur);
    csv += `${k}\t${tfc.time}\t${megs / tfc.time}\n`;
    console.log(`k:${k} tfc:${tfc.time} tfc/s:${megs / tfc.time}`);
  }
  // sweep KB chunkSize
  const sweep = [
    1, 2, 4, 8, 16, 32, 64, 96, 128, 160, 192, 256,
    320, 384, 448, 512, 576, 640, 704, 768, 832, 896, 960, 1024
  ];
  sweep.forEach(k => _test(k));
  console.log(csv);
}

function compareEncChunkSize() {
  const megs = 10;
  let csv = '';
  function _test(k) {
    const chunkSize = 1024 * k;
    const dcs = [
      data_chunk(megs, chunkSize),
      data_chunk(megs, chunkSize),
      data_chunk(megs, chunkSize)
    ];
    const dc = dcs.reduce((prev, cur) => prev.time < cur.time ? prev : cur);
    csv += `${k}\t${dc.time}\t${megs / dc.time}\n`;
    console.log(`k:${k} dc:${dc.time} dc/s:${megs / dc.time}`);
  }
  // sweep KB chunkSize
  const sweep = [
    1, 2, 4, 8, 16, 32, 64, 96, 128, 160, 192, 256,
    320, 384, 448, 512, 576, 640, 704, 768, 832, 896, 960, 1024
  ];
  sweep.forEach(k => _test(k));
  console.log(csv);
}

compareImpl();
//compareDecChunkSize();
//compareEncChunkSize();
