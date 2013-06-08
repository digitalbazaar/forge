/**
 * Node.js module for Forge.
 *
 * @author Dave Longley
 *
 * Copyright 2011-2013 Digital Bazaar, Inc.
 */
(function() {
var deps = [
  './aes',
  './aesCipherSuites',
  './asn1',
  './debug',
  './des',
  './hmac',
  './log',
  './pbkdf2',
  './pkcs7',
  './pkcs12',
  './pki',
  './prng',
  './pss',
  './random',
  './rc2',
  './task',
  './tls',
  './util',
  './md',
  './mgf1'
];
var cjsDefine = null;
if(typeof define !== 'function') {
  // CommonJS -> AMD
  if(typeof module === 'object' && module.exports) {
    cjsDefine = function(ids, factory) {
      module.exports = factory.apply(null, ids.map(function(id) {
        return require(id);
      }));
    };
  }
  // <script>
  else {
    if(typeof forge === 'undefined') {
      forge = {};
    }
    initModule(forge);
  }
}
// AMD
if(cjsDefine || typeof define === 'function') {
  // define module AMD style
  (cjsDefine || define)(deps, function() {
    var forge = {};
    var mods = Array.prototype.slice.call(arguments);
    for(var i = 0; i < mods.length; ++i) {
      mods[i](forge);
    }
    return forge;
  });
}
})();
