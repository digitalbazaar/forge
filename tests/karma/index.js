// The karma tests include all standard unit tests...
require('../unit');

// ...plus some tests that can only run in the browser (e.g. web worker compatibility)
require('./rsa');