/**
 * Node.js module for Forge.
 *
 * @author Dave Longley
 *
 * Copyright 2011-2013 Digital Bazaar, Inc.
 */
(function() {
var name = 'forge';
var deps = [
  './aes',
  './aesCipherSuites',
  './asn1',
  './debug',
  './des',
  './hmac',
  './log',
  './pbkdf2',
  './pem',
  './pkcs7',
  './pkcs1',
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
var nodeDefine = null;
if(typeof define !== 'function') {
  // NodeJS -> AMD
  if(typeof module === 'object' && module.exports) {
    nodeDefine = function(ids, factory) {
      factory(require, module);
    };
  }
  // <script>
  else {
    if(typeof forge === 'undefined') {
      forge = {};
    }
  }
}
// AMD
var defineDeps = ['require', 'module'].concat(deps);
var defineFunc = function(require, module) {
  module.exports = function(forge) {
    var mods = deps.map(function(dep) {
      return require(dep);
    });
    // handle circular dependencies
    forge = forge || {};
    forge.defined = forge.defined || {};
    if(forge.defined[name]) {
      return forge[name];
    }
    forge.defined[name] = true;
    for(var i = 0; i < mods.length; ++i) {
      mods[i](forge);
    }
    return forge[name];
  };
  module.exports(module.exports);
};
if(nodeDefine) {
  nodeDefine(defineDeps, defineFunc);
}
else if(typeof define === 'function') {
  define([].concat(defineDeps), function() {
    defineFunc.apply(null, Array.prototype.slice.call(arguments, 0));
  });
}
})();
