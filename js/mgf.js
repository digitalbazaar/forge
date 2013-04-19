/**
 * Node.js module for Forge mask generation functions.
 *
 * @author Stefan Siegl
 *
 * Copyright 2012 Stefan Siegl <stesie@brokenpipe.de>
 */
(function() {
var deps = {
  mgf1: './mgf1'
};
var name = 'mgf';
function initModule(forge) {
/* ########## Begin module implementation ########## */


forge.mgf.mgf1 = forge.mgf1;


/* ########## Begin module wrapper ########## */
}
var cjsDefine = null;
if(typeof define !== 'function') {
  // CommonJS -> AMD
  if(typeof exports === 'object') {
    cjsDefine = function(ids, factory) {
      module.exports = factory.apply(null, ids.map(function(id) {
        return require(id);
      }));
    };
  }
  // <script>
  else {
    var forge = window.forge = window.forge || {};
    forge[name] = forge[name] || {};
    initModule(forge);
  }
}
// AMD
if(cjsDefine || typeof define === 'function') {
  var ids = [];
  var assigns = [];
  // Convert `deps` dependency declaration tree into AMD dependency list.
  function forEachDep(path, deps) {
    function assign(path) {
      var index = ids.length;
      ids.push(deps[path[path.length-1]]);
      // Create helper function used after import below.
      assigns.push(function(forge, args) {
        var id;
        while(path.length > 1) {
          id = path.shift();
          forge = forge[id] = forge[id] || {};
        }
        forge[path[0]] = args[index];
      });
    }
    for(var alias in deps) {
      if(typeof deps[alias] === 'string') {
        assign(path.concat(alias));
      }
      else {
        forEachDep(path.concat(alias), deps[alias]);
      }
    }
    return forge;
  }
  forEachDep([], deps);
  // Declare module AMD style.
  (cjsDefine || define)(ids, function() {
    var args = arguments;
    var forge = {};
    // Assemble AMD imported modules into `forge` dependency tree.
    assigns.forEach(function(assign) {
      assign(forge, args);
    });
    forge[name] = forge[name] || {};
    initModule(forge);
    return forge[name];
  });
}
})();
