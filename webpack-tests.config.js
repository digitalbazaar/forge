/**
 * Forge webpack build rules for unit tests.
 *
 * @author Digital Bazaar, Inc.
 *
 * Copyright 2011-2016 Digital Bazaar, Inc.
 */
const path = require('path');

module.exports = {
  entry: {
    'forge-tests': './tests/unit/index.js'
  },
  output: {
    path: path.join(__dirname, 'dist'),
    filename: '[name].js',
    library: '[name]',
    libraryTarget: 'umd'
  },
  node: {
    Buffer: false,
    process: false,
    crypto: false,
    setImmediate: false
  }
};
