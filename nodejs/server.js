var PATH = require('path');
var express = require('express');
var PORT = 8083;

exports.main = function(callback) {
  try {
    var app = express();

    mountStaticDir(app, /^\/mocha\/(.*)$/, PATH.join(__dirname, 'node_modules/mocha'));
    app.get(/^\//, express.static(PATH.join(__dirname, 'ui')));

    var server = app.listen(PORT);

    console.log('open http://localhost:' + PORT + '/');

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
