var ASSERT = require('assert');
var RSA = require('../../lib/rsa');

// The worker-loader build the ./testWorker.js as a separate bundle and returns a constructor
// that saves us from having to know the public script path
// I.e.: new Worker('path/to/public/script.js') becomes new TestWorker()
var TestWorker = require('worker-loader!./testWorker');
var testWorker = new TestWorker();


describe('rsa', function() {
  it('should generate key pairs when running forge in a web worker', function(done) {
    // Make test worker call rsa.generateKeyPair() on its own side 
    testWorker.postMessage({ method: 'rsa.generateKeyPair' });

    // Wait for a result (see testWorker.js for what event data to expect)
    testWorker.addEventListener('message', function (event) {
      ASSERT.equal(event.data.type, 'success');
      // This is primarily to ensure that the node-forge code runs successfully in the worker
      // (e.g. no usages of `window` or similar). So, comparing for structural sanity of the result
      // only should be fine
      ASSERT.equal(typeof event.data.result.publicKey, 'string');
      ASSERT.equal(typeof event.data.result.privateKey, 'string');

      done();
    });
  });
});
