// The karma tests include all standard unit tests...
require('../unit');

// ...plus some tests that can only run in the browser (e.g. web worker
// compatibility)
// FIXME: if browserify testing is dropped, enable this and remove browserify
// specific code from karma.config.js
//require('./web-worker-rsa');
