var express = require('express');
var path = require('path');
var PORT = 8083;

exports.main = function(callback) {
  try {
    var app = express();

    // forge
    app.use('/forge', express.static(path.join(__dirname, '..', 'dist')));

    // unit tests support
    app.use('/mocha',
      express.static(path.join(__dirname, '..', 'node_modules', 'mocha')));

    // legacy tests support
    app.use('/forge/SocketPool.swf',
      express.static(path.join(__dirname, '..', 'swf', 'SocketPool.swf')));
    app.use('/forge/prime.worker.js',
      express.static(path.join(__dirname, '..', 'lib', 'prime.worker.js')));
    app.use('/forge/jsbn.js',
      express.static(path.join(__dirname, '..', 'lib', 'jsbn.js')));
    app.use('/result.txt',
      express.static(path.join(__dirname, 'legacy', 'result.txt')));

    // main
    app.get(/^\//, express.static(path.join(__dirname)));

    var server = app.listen(PORT);

    console.log('Forge test server running:');
    console.log('http://localhost:' + PORT + '/');

    return callback(null, {
      server: server,
      port: PORT
    });
  } catch(err) {
    return callback(err);
  }
};

function mountStaticDir(app, route, path) {
  app.get(route, function(req, res, next) {
    var originalUrl = req.url;
    req.url = req.params[0];
    express.static(path)(req, res, function() {
      req.url = originalUrl;
      return next.apply(null, arguments);
    });
  });
}

if(require.main === module) {
  exports.main(function(err) {
    if(err) {
      console.error(err.stack);
      process.exit(1);
    }
  });
}
