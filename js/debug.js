/**
 * Debugging support for web applications.
 *
 * @author David I. Lehn <dlehn@digitalbazaar.com>
 *
 * Copyright 2008-2012 Digital Bazaar, Inc.
 */
(function() {
var deps = {};
var name = 'debug';
function initModule(forge) {
/* ########## Begin module implementation ########## */


// Private storage for debugging.
// Useful to expose data that is otherwise unviewable behind closures.
// NOTE: remember that this can hold references to data and cause leaks!
// format is "forge._debug.<modulename>.<dataname> = data"
// Example:
// (function() {
//   var cat = 'forge.test.Test'; // debugging category
//   var sState = {...}; // local state
//   forge.debug.set(cat, 'sState', sState);
// })();
forge.debug.storage = {};

/**
 * Gets debug data. Omit name for all cat data  Omit name and cat for
 * all data.
 *
 * @param cat name of debugging category.
 * @param name name of data to get (optional).
 * @return object with requested debug data or undefined.
 */
forge.debug.get = function(cat, name) {
  var rval;
  if(typeof(cat) === 'undefined') {
    rval = forge.debug.storage;
  }
  else if(cat in forge.debug.storage) {
    if(typeof(name) === 'undefined') {
      rval = forge.debug.storage[cat];
    }
    else {
      rval = forge.debug.storage[cat][name];
    }
  }
  return rval;
};

/**
 * Sets debug data.
 *
 * @param cat name of debugging category.
 * @param name name of data to set.
 * @param data data to set.
 */
forge.debug.set = function(cat, name, data) {
  if(!(cat in forge.debug.storage)) {
    forge.debug.storage[cat] = {};
  }
  forge.debug.storage[cat][name] = data;
};

/**
 * Clears debug data. Omit name for all cat data. Omit name and cat for
 * all data.
 *
 * @param cat name of debugging category.
 * @param name name of data to clear or omit to clear entire category.
 */
forge.debug.clear = function(cat, name) {
  if(typeof(cat) === 'undefined') {
    forge.debug.storage = {};
  }
  else if(cat in forge.debug.storage) {
    if(typeof(name) === 'undefined') {
      delete forge.debug.storage[cat];
    }
    else {
      delete forge.debug.storage[cat][name];
    }
  }
};


/* ########## Begin module wrapper ########## */
}
var cjsDefine = null;
if (typeof define !== 'function') {
  // CommonJS -> AMD
  if (typeof exports === 'object') {
    cjsDefine = function(ids, factory) {
      module.exports = factory.apply(null, ids.map(function(id) {
        return require(id);
      }));
    }
  } else
  // <script>
  {
    var forge = window.forge = window.forge || {};
    forge[name] = forge[name] || {};
    initModule(forge);
  }
}
// AMD
if (cjsDefine || typeof define === 'function') {
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
    for (var alias in deps) {
      if (typeof deps[alias] === 'string') {
        assign(path.concat(alias));
      } else {
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
    var exports = forge[name] = forge[name] || {};
    initModule(forge);
    return exports;
  });
}
})();
