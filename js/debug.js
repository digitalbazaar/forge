/**
 * Debugging support for web applications.
 *
 * @author David I. Lehn <dlehn@digitalbazaar.com>
 *
 * Copyright 2008-2013 Digital Bazaar, Inc.
 */

/* DEBUG API */
var debug = {};

module.exports = debug;

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
debug.storage = {};

/**
 * Gets debug data. Omit name for all cat data  Omit name and cat for
 * all data.
 *
 * @param cat name of debugging category.
 * @param name name of data to get (optional).
 * @return object with requested debug data or undefined.
 */
debug.get = function(cat, name) {
  var rval;
  if(typeof(cat) === 'undefined') {
    rval = debug.storage;
  } else if(cat in debug.storage) {
    if(typeof(name) === 'undefined') {
      rval = debug.storage[cat];
    } else {
      rval = debug.storage[cat][name];
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
debug.set = function(cat, name, data) {
  if(!(cat in debug.storage)) {
    debug.storage[cat] = {};
  }
  debug.storage[cat][name] = data;
};

/**
 * Clears debug data. Omit name for all cat data. Omit name and cat for
 * all data.
 *
 * @param cat name of debugging category.
 * @param name name of data to clear or omit to clear entire category.
 */
debug.clear = function(cat, name) {
  if(typeof(cat) === 'undefined') {
    debug.storage = {};
  } else if(cat in debug.storage) {
    if(typeof(name) === 'undefined') {
      delete debug.storage[cat];
    } else {
      delete debug.storage[cat][name];
    }
  }
};
