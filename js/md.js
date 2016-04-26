/**
 * Node.js module for Forge message digests.
 *
 * @author Dave Longley
 *
 * Copyright 2011-2014 Digital Bazaar, Inc.
 */
var md5 = require("./md5");
var sha1 = require("./sha1");
var sha256 = require("./sha256");
var md = {};
md.algorithms = {
  md5: md5,
  sha1: sha1,
  sha256: sha256
};
md.md5 = md5;
md.sha1 = sha1;
md.sha256 = sha256;
module.exports = md;
