/**
 * Forge webpack build rules.
 *
 * @author Digital Bazaar, Inc.
 *
 * Copyright 2011-2016 Digital Bazaar, Inc.
 */
const path = require('path');
const webpack = require('webpack');

// build multiple outputs
module.exports = [];

// custom setup for each output
// all built files will export the "forge" library but with different content
const outputs = [
  // core forge library crypto and utils
  {
    entry: ['./lib/index.js'],
    filenameBase: 'forge'
  },
  // core forge library + extra utils and networking support
  {
    entry: ['./lib/index.all.js'],
    filenameBase: 'forge.all'
  },
  // jsbn module (used from prime.worker.js)
  {
    entry: ['./lib/jsbn.js', './lib/forge.js'],
    filenameBase: 'jsbn'
  }
  // custom builds can be created by specifying the high level files you need
  // webpack will pull in dependencies as needed
  // Note: if using UMD or similar, add forge.js *last* to properly export
  // the top level forge namespace.
  //{
  //  entry: ['./lib/sha1.js', ..., './lib/forge.js'],
  //  filenameBase: 'forge.custom'
  //  libraryTarget: 'umd'
  //}
];

outputs.forEach((info) => {
  // common to bundle and minified
  const common = {
    // each output uses the "forge" name but with different contents
    entry: {
      forge: info.entry
    },
    // disable various node shims as forge handles this manually
    node: {
      Buffer: false,
      process: false,
      crypto: false,
      setImmediate: false
    }
  };

  // plain unoptimized unminified bundle
  const bundle = Object.assign({}, common, {
    output: {
      path: path.join(__dirname, 'dist'),
      filename: info.filenameBase + '.js',
      library: '[name]',
      libraryTarget: info.libraryTarget || 'umd'
    }
  });

  // optimized and minified bundle
  const minify = Object.assign({}, common, {
    output: {
      path: path.join(__dirname, 'dist'),
      filename: info.filenameBase + '.min.js',
      library: '[name]',
      libraryTarget: info.libraryTarget || 'umd'
    },
    devtool: 'source-map',
    plugins: [
      new webpack.optimize.UglifyJsPlugin({
        compress: {
          warnings: true
        },
        output: {
          comments: false
        }
        //beautify: true
      })
    ]
  });

  module.exports.push(bundle);
  module.exports.push(minify);
});
