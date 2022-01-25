/**
 * Forge webpack build rules for unit tests.
 *
 * @author Digital Bazaar, Inc.
 *
 * Copyright 2011-2016 Digital Bazaar, Inc.
 */
const path = require('path');

module.exports = {
  mode: 'development',
  entry: {
    'forge-tests': './tests/unit/index.js'
  },
  output: {
    library: '[name]',
    libraryTarget: 'umd'
  }
};
