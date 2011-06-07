/**
 * Node.js module for Forge.
 * 
 * @author Dave Longley
 * 
 * Copyright 2011 Digital Bazaar, Inc.
 */
var forge =
{
   aes: require('./aes'),
   asn1: require('./asn1'),
   debug: require('./debug'),
   hmac: require('./hmac'),
   jsonld: require('./jsonld'),
   log: require('./log'),
   pkcs5: require('./pbkdf2'),
   pki: require('./pki'),
   prng: require('./prng'),
   random: require('./random'),
   task: require('./task'),
   tls: require('./tls'),
   util: require('./util'),
   md: require('./md')
};
forge.pki.oids = require('./oids');
forge.pki.rsa = require('./rsa');
module.exports = forge;
