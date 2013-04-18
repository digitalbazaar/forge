
const PATH = require('path');
const EXPRESS = require('express');

const PORT = 8080;


exports.main = function(callback) {
    try {
        var app = EXPRESS();

        mountStaticDir(app, /^\/forge\/(.*)$/, PATH.join(__dirname, '../js'));
        mountStaticDir(app, /^\/test\/(.*)$/, PATH.join(__dirname, 'test'));
        mountStaticDir(app, /^\/mocha\/(.*)$/, PATH.join(__dirname, 'node_modules/mocha'));
        mountStaticDir(app, /^\/chai\/(.*)$/, PATH.join(__dirname, 'node_modules/chai'));
        app.get(/^\//, EXPRESS.static(PATH.join(__dirname, 'ui')));

        var server = app.listen(PORT);

        console.log('open http://localhost:' + PORT + '/');

        return callback(null, {
            server: server,
            port: PORT
        });

    } catch(err) {
        return callback(err);
    }
}


function mountStaticDir(app, route, path) {
    app.get(route, function(req, res, next) {
        var originalUrl = req.url;
        req.url = req.params[0];
        EXPRESS.static(path)(req, res, function() {
            req.url = originalUrl;
            return next.apply(null, arguments);
        });
    });
};


if (require.main === module) {
    exports.main(function(err) {
        if (err) {
            console.error(err.stack);
            process.exit(1);
        }
    });
}
