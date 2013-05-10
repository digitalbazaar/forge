/* Bundle and minify Forge RSA and dependencies. */
var fs = require('fs');
var path = require('path');
//var UglifyJS = require('uglify-js');

// list dependencies in order
var files = [
  'util.js',
  'md5.js',
  'sha1.js',
  'aes.js',
  'prng.js',
  'random.js',
  'hmac.js',
  'jsbn.js',
  'oids.js',
  'asn1.js',
  'rsa.js',
  'pki.js'
];
files = files.map(function(file) {
  return path.join(__dirname, 'js', file);
});

// bundle and minify JS
console.log('Creating RSA bundle...');

var bundle = path.join(__dirname, 'js', 'forge.rsa.bundle.js');

// FIXME: minification is turned off at the moment because it seems to have
// negatively affected performance
//fs.writeFileSync(bundle, UglifyJS.minify(files).code);
var concat = '';
files.forEach(function(file) {
  concat += fs.readFileSync(file);
});
fs.writeFileSync(bundle, concat);

console.log('RSA bundle written to: ' + bundle);
