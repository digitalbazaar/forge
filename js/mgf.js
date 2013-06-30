/**
 * Node.js module for Forge mask generation functions.
 *
 * @author Stefan Siegl
 *
 * Copyright 2012 Stefan Siegl <stesie@brokenpipe.de>
 */
(function() {
/* ########## Begin module implementation ########## */
function initModule(forge) {

forge.mgf = forge.mgf || {};
forge.mgf.mgf1 = forge.mgf1;

} // end module implementation

/* ########## Begin module wrapper ########## */
var name = 'mgf';
var deps = ['./mgf1'];
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
    initModule(forge);
  }
}
// AMD
var defineDeps = ['require', 'module'].concat(deps);
var defineFunc = function(require, module) {
  module.exports = function(forge) {
    var mods = deps.map(function(dep) {
      return require(dep);
    }).concat(initModule);
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
