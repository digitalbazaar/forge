/**
 * Node.js module for Forge.
 *
 * @author Dave Longley
 *
 * Copyright 2011-2014 Digital Bazaar, Inc.
 */
// default options
var options;
if(typeof forge !== 'undefined') {
  options = forge;
} else {
  options = {
    disableNativeCode: false
  };
}
function makeForge(options) {
  var self = this;
  // create new forge container function
  // can be called with new options to create independent copy
  var forge = function() {
    return makeForge(options);
  };
  function set(value, key) {
    forge[key] = value;
  }
  // copy old properties
  Object.keys(self).forEach(set);
  // set options
  Object.keys(options).forEach(set);
  return forge;
}
module.exports = makeForge(options);
