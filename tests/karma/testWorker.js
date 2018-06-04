var RSA = require('../../lib/rsa');
var PKI = require('../../lib/pki');

// The following code allows main thread scripts to make the worker call certain forge APIs within
// the worker (primarily to ensure compatibility)
// We  define a light-weight protocol to simplify testing 
self.addEventListener('message', function (event) {
      
      // Test scripts call worker.postMessage(data)` – we can access the payload via event.data

      // data.method defines what the worker should call (we skip sophisticated reflection-magic,
      // argument passing, etc. for now)
      switch (event.data.method) {
            case 'rsa.generateKeyPair':
                  RSA.generateKeyPair({ bits: 512, workers: -1 }, function(error, keyPair) {
                        // We signal the outcome of the call via event.data with...
                        if (error) {
                              // ...event.data.type === 'error' if the call failed
                              self.postMessage({
                                    type: 'error',
                                    result: error.toString()
                              });
                        } else {
                              // ...event.data.type === 'success' if the call succeeded
                              self.postMessage({
                                    type: 'success',
                                    result: {
                                          publicKey: PKI.publicKeyToPem(keyPair.publicKey),
                                          privateKey: PKI.privateKeyToPem(keyPair.privateKey),
                                    }
                              });
                        }
                  });
      }
});