var ASSERT = require('assert');

// The worker-loader build the ./testWorker.js as a separate bundle and returns
// a constructor that saves us from having to know the public script path
// I.e.: new Worker('path/to/public/script.js') becomes new TestWorker()
var TestWorker = require('worker-loader!./testWorker');
var testWorker = new TestWorker();

function _log(message) {
  console.log('[main] ' + message);
}

describe('web worker rsa', function() {
  it('should generate key pairs when running forge in a web worker', function(done) {
    // Make test worker call rsa.generateKeyPair() on its own side
    //testWorker.postMessage({type: 'ping'});
    testWorker.postMessage({type: 'rsa.generateKeyPair'});

    // Wait for a result (see testWorker.js for what event data to expect)
    testWorker.addEventListener('message', function(event) {
      //_log('message type: ' + event.data.type);
      switch(event.data.type) {
        case 'success':
          // This is primarily to ensure that the node-forge code runs
          // successfully in the worker (e.g. no usages of `window` or
          // similar). So, comparing for structural sanity of the result only
          // should be fine.
          ASSERT.equal(typeof event.data.keypair, 'object');
          ASSERT.equal(typeof event.data.keypair.publicKey, 'string');
          ASSERT.equal(typeof event.data.keypair.privateKey, 'string');

          // done with worker tests
          testWorker.terminate();

          done();
          break;
        case 'error':
          ASSERT.fail('web worker error: ' + event.data.result);
          break;
        case 'log':
          console.log('[worker] ' + event.data.message);
          break;
        case 'pong':
          // for debugging worker is alive
          //_log('pong');
          break;
        case 'stop':
          testWorker.terminate();
          break;
        default:
          console.log('UNKNOWN MESSAGE TYPE: ' + event.data.type);
      }
    });
  });
});
