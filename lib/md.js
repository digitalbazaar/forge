/**
 * Node.js module for Forge message digests.
 *
 * @author Dave Longley
 *
 * Copyright 2011-2014 Digital Bazaar, Inc.
 */
var forge = require('./forge');
require('./md5');
require('./sha1');
require('./sha256');
require('./sha512');

module.exports = forge.md = forge.md || {};
forge.md.algorithms = {
  md5: forge.md5,
  sha1: forge.sha1,
  sha256: forge.sha256
};
forge.md.md5 = forge.md5;
forge.md.sha1 = forge.sha1;
forge.md.sha256 = forge.sha256;
