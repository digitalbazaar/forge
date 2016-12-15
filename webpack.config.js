const path = require('path');
const webpack = require('webpack');

// common to bundle and minified
const common = {
  entry: {
    forge: './lib/index.js',
    //sha1: ['./lib/sha1.js']
    //...
  },
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
    filename: '[name].js',
    library: '[name]',
    libraryTarget: 'umd'
  }
});

// optimized and minified bundle
const minify = Object.assign({}, common, {
  output: {
    path: path.join(__dirname, 'dist'),
    filename: '[name].min.js',
    library: '[name]',
    libraryTarget: 'umd'
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

module.exports = [bundle, minify];
