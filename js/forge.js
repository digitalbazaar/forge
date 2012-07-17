/**
 * Node.js module for Forge.
 *
 * @author Dave Longley
 *
 * Copyright 2011-2012 Digital Bazaar, Inc.
 */
var forge = {
  aes: require('./aes'),
  asn1: require('./asn1'),
  debug: require('./debug'),
  des: require('./des'),
  hmac: require('./hmac'),
  log: require('./log'),
  pkcs5: require('./pbkdf2'),
  pkcs7: require('./pkcs7'),
  pkcs12: require('./pkcs12'),
  pki: require('./pki'),
  prng: require('./prng'),
  pss: require('./pss'),
  random: require('./random'),
  rc2: require('./rc2'),
  task: require('./task'),
  tls: require('./tls'),
  util: require('./util'),
  md: require('./md'),
  mgf: {
    mgf1: require('./mgf1')
  }
};
forge.pki.oids = require('./oids');
forge.pki.rsa = require('./rsa');
module.exports = forge;
