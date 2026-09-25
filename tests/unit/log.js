var ASSERT = require('assert');
require('../../lib/log');
var forge = require('../../lib/forge');

function isIsolatedNode() {
  return typeof process !== 'undefined' &&
    process.versions &&
    process.versions.node &&
    typeof process.execPath === 'string';
}

function reloadLog(setup) {
  var logPath = require.resolve('../../lib/log.js');
  var hadWindow = Object.prototype.hasOwnProperty.call(global, 'window');
  var savedWindow = global.window;
  var savedURL = global.URL;
  var savedLog = {};
  var keys = Object.keys(forge.log);
  for(var i = 0; i < keys.length; i++) {
    savedLog[keys[i]] = forge.log[keys[i]];
  }
  var cached = require.cache[logPath];
  delete require.cache[logPath];
  try {
    setup();
    require('../../lib/log.js');
  } finally {
    if(hadWindow) {
      global.window = savedWindow;
    } else {
      delete global.window;
    }
    global.URL = savedURL;
    delete require.cache[logPath];
    if(cached) {
      require.cache[logPath] = cached;
    }
    var restoreKeys = Object.keys(savedLog);
    for(var j = 0; j < restoreKeys.length; j++) {
      forge.log[restoreKeys[j]] = savedLog[restoreKeys[j]];
    }
  }
}

(function() {
  describe('log', function() {
    it('should load when URL is not a constructor (issue #1117)', function() {
      if(!isIsolatedNode()) {
        this.skip();
      }
      ASSERT.doesNotThrow(function() {
        reloadLog(function() {
          global.window = {location: {href: 'https://example.com/'}};
          global.URL = undefined;
        });
      });
    });

    it('should load when window.location.href is missing (issue #1117)', function() {
      if(!isIsolatedNode()) {
        this.skip();
      }
      ASSERT.doesNotThrow(function() {
        reloadLog(function() {
          global.window = {location: {}};
        });
      });
    });
  });
})();
