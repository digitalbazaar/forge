
const SERVER = require("../server");
const GRUNT = require('grunt');


describe('browser', function() {

    it('should run tests', function(done) {

        this.timeout(60 * 1000);

        return SERVER.main(function(err, info) {
            if (err) return done(err);

            GRUNT.initConfig({
                mocha: {
                    all: {
                        options: {
                            reporter: 'List',
                            urls: [
                                'http://localhost:' + info.port + '/index.html'
                            ]
                        }
                    }
                }
            });

            GRUNT.loadNpmTasks('grunt-mocha');

            GRUNT.registerInitTask('default', function() {
                GRUNT.task.run(['mocha']);
            });
            GRUNT.tasks(['default'], {
                //debug: true
            }, function() {
                if (err) return done(err);
                return info.server.close(function() {
                    return done(null);
                });
            });
        });
    });

});
