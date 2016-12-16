const path = require('path');
const webpack = require('webpack');

module.exports = {
  entry: {
    'forge-tests': './ui/test.js'
  },
  output: {
    path: path.join(__dirname, 'ui'),
    filename: '[name].js',
    library: '[name]',
    libraryTarget: 'umd'
  },
  plugins: [
    /*
    new webpack.optimize.UglifyJsPlugin({
      compress: {
        warnings: true
      },
      output: {
        comments: false
      }
      //beautify: true
    })
    */
  ],
  node: {
    Buffer: false,
    process: false,
    crypto: false,
    setImmediate: false
  }
};
