/**
 * Javascript implementation of mask generation function MGF1.
 *
 * @author Stefan Siegl
 *
 * Copyright (c) 2012 Stefan Siegl <stesie@brokenpipe.de>
 */
(function() {
var deps = {
  util: './util'
};
var name = 'mgf1';
function initModule(forge) {
/* ########## Begin module implementation ########## */


var mgf1 = forge.mgf1;

forge.mgf = forge.mgf || {};
forge.mgf.mgf1 = mgf1;

/**
 * Creates a MGF1 mask generation function object.
 *
 * @return a mask generation function object.
 */
mgf1.create = function(md) {
  var mgf = {
    /**
     * Generate mask of specified length.
     *
     * @param {String} seed The seed for mask generation.
     * @param maskLen Number of bytes to generate.
     * @return {String} The generated mask.
     */
    generate: function(seed, maskLen) {
      /* 2. Let T be the empty octet string. */
      var t = new forge.util.ByteBuffer();

      /* 3. For counter from 0 to maskLen / hLen - 1, do the following: */
      var len = Math.ceil(maskLen / md.digestLength);
      for(var i = 0; i < len; i++) {
        /* a. Convert counter to an octet string C of length 4 octets */
        var c = new forge.util.ByteBuffer();
        c.putInt32(i);

        /* b. Concatenate the hash of the seed mgfSeed and C to the octet
         * string T: */
        md.start();
        md.update(seed + c.getBytes());
        t.putBuffer(md.digest());
      }

      /* Output the leading maskLen octets of T as the octet string mask. */
      t.truncate(t.length() - maskLen);
      return t.getBytes();
    }
  };

  return mgf;
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
    forge[name] = forge[name] || {};
    initModule(forge);
    return forge[name];
  });
}
})();
