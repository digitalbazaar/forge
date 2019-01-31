var RSA = require('../../lib/rsa');
var PKI = require('../../lib/pki');

// log on main thread
function _log(message) {
  self.postMessage({
    type: 'log',
    message: message
  });
}

// The following code allows main thread scripts to make the worker call
// certain forge APIs within the worker (primarily to ensure compatibility)
// We define a light-weight protocol to simplify testing
// @param event
//          event.data {Object} message content
//          event.data.type {String} message type
//          event.data.* {Any} type specific data
self.addEventListener('message', function(event) {
  // Test scripts call worker.postMessage(data)
  // we can access the payload via event.data

  //_log('message type: ' + event.data.type);

  // data.type defines what the worker should call
  switch(event.data.type) {
    case 'ping':
      self.postMessage({
        type: 'pong'
      });
      break;
    case 'rsa.generateKeyPair':
      //_log('keygen start');
      //RSA.generateKeyPair({bits: 512, workers: -1}, function(error, keyPair) {
      RSA.generateKeyPair({bits: 512, workers: 1}, function(error, keyPair) {
        //_log('keygen done');
        // We signal the outcome of the call via event.data with...
        if(error) {
          // ...event.data.type === 'error' if the call failed
          self.postMessage({
            type: 'error',
            error: error.toString()
          });
        } else {
          // ...event.data.type === 'success' if the call succeeded
          self.postMessage({
            type: 'success',
            keypair: {
              publicKey: PKI.publicKeyToPem(keyPair.publicKey),
              privateKey: PKI.privateKeyToPem(keyPair.privateKey)
            }
          });
        }
      });
      break;
    case 'stop':
      self.close();
      break;
    default:
      self.postMessage({
        type: 'error',
        error: 'Unknown message type: ' + event.data.type
      });
  }
});
