var server = require('../server');
var grunt = require('grunt');
//var path = require('path');
//var fs = require("fs");

describe('browser', function() {
  it('should run tests', function(done) {
    this.timeout(60 * 1000 * 5);

    return server.main(function(err, info) {
      if(err) {
        return done(err);
      }

      //var globbed = fs.readdirSync("test").filter(function(val) {
      //  return val.indexOf("browser") === -1;
      //}).map(function(val) {
      //  return "../nodejs/test/" + val.slice(0, -3);
      //});
      //console.log(globbed);
      grunt.initConfig({
        webpack: {
          forge_bundle: {
            //loaders: [
            //  { test: /^..\/nodejs\/test\//, loader: "mocha" }
            //],
            context: __dirname + "../../../js",
            entry: ["../nodejs/ui/test"],
            output: {
              library: "forge-bundle",
              path: "ui",
              filename: "forge.bundle.js",
              libraryTarget: "umd"
            }
          }
        },
        mocha_phantomjs: {
          all: {
            options: {
              reporter: 'List',
              urls: ['http://localhost:' + info.port + '/index.html']
            }
          }
        }
      });

      grunt.loadNpmTasks('grunt-mocha-phantomjs');
      grunt.loadNpmTasks('grunt-webpack');

      grunt.registerInitTask('default', function() {
        grunt.task.run(['webpack']);
        grunt.task.run(['mocha_phantomjs']);
      });
      grunt.tasks(['default'], {
        //debug: true
      }, function() {
        if(err) {
          return done(err);
        }
        // finish immediately
        done(null);
        return info.server.close();
      });
    });
  });
});
