/**
 * Node.js module for Forge message digests.
 *
 * @author Dave Longley
 *
 * Copyright 2011-2014 Digital Bazaar, Inc.
 */
(function() {
/* ########## Begin module implementation ########## */
function initModule(forge) {

forge.md = forge.md || {};
forge.md.algorithms = {
  md5: forge.md5,
  sha1: forge.sha1,
  sha256: forge.sha256
};
forge.md.md5 = forge.md5;
forge.md.sha1 = forge.sha1;
forge.md.sha256 = forge.sha256;

} // end module implementation

})();
