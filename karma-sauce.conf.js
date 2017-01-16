/*!
 * Karma Sauce Labs configuration
 *
 * `SAUCE_USERNAME` and `SAUCE_ACCESS_KEY` environmental variables should
 * be set. For configuration details, see: https://github.com/karma-runner/karma-sauce-launcher
 */
module.exports = function(config) {
  // bundler to test: webpack, browserify
  var bundler = process.env.BUNDLER || 'webpack';

  var frameworks = ['mocha'];
  // main bundle preprocessors
  var preprocessors = [];
  // webworker bundle preprocessors (always use webpack)
  var workerPreprocessors = ['webpack'];

  if(bundler === 'browserify') {
    frameworks.push(bundler);
    preprocessors.push(bundler);
  } else if(bundler === 'webpack') {
    preprocessors.push(bundler);
  } else {
    throw Error('Unknown bundler');
  }

  // Define an unlimited number of browser/OS combinations here. Sauce Labs
  // will manage concurrency based on user's account restrictions.
  // Platform Configurator Tool: https://wiki.saucelabs.com/display/DOCS/Platform+Configurator#/
  var customLaunchers = {
    sl_chrome: {
      base: 'SauceLabs',
      browserName: 'chrome',
      platform: 'Linux',
      version: '48.0'
    },
    sl_firefox: {
      base: 'SauceLabs',
      browserName: 'firefox',
      platform: 'Linux',
      version: '45.0'
    },
    sl_ios_safari_10: {
      base: 'SauceLabs',
      browserName: 'safari',
      platform: 'OS X 10.11',
      version: '10.0'
    },
    sl_ios_safari_9: {
      base: 'SauceLabs',
      browserName: 'safari',
      platform: 'OS X 10.11',
      version: '9.0'
    },
    sl_ie_11: {
      base: 'SauceLabs',
      browserName: 'internet explorer',
      platform: 'Windows 7',
      version: '11.0'
    },
    sl_edge_14: {
      base: 'SauceLabs',
      browserName: 'MicrosoftEdge',
      platform: 'Windows 10',
      version: '14.14393'
    },
    sl_edge_13: {
      base: 'SauceLabs',
      browserName: 'MicrosoftEdge',
      platform: 'Windows 10',
      version: '13.10586'
    }
  };

  config.set({
    // base path that will be used to resolve all patterns (eg. files, exclude)
    basePath: '',

    // frameworks to use
    // available frameworks: https://npmjs.org/browse/keyword/karma-adapter
    frameworks: frameworks,

    // list of files / patterns to load in the browser
    files: [
      'tests/unit/index.js',
      // for webworkers
      {
        pattern: 'lib/prime.worker.js',
        watched: false, included: false, served: true, nocache: false
      }
    ],

    // list of files to exclude
    exclude: [
    ],

    // preprocess matching files before serving them to the browser
    // available preprocessors: https://npmjs.org/browse/keyword/karma-preprocessor
    preprocessors: {
      'tests/unit/index.js': preprocessors,
      'lib/prime.worker.js': workerPreprocessors
    },

    browserify: {
      debug: true
      //transform: ['uglifyify']
    },

    // web server port
    port: 9876,

    // enable / disable colors in the output (reporters and logs)
    colors: true,

    // level of logging
    // possible values: config.LOG_DISABLE || config.LOG_ERROR || config.LOG_WARN || config.LOG_INFO || config.LOG_DEBUG
    logLevel: config.LOG_INFO,

    // enable / disable watching file and executing tests whenever any file changes
    autoWatch: false,

    sauceLabs: {
      testName: 'Forge Unit Tests',
      startConnect: true
    },
    captureTimeout: 180000,
    customLaunchers: customLaunchers,
    browsers: Object.keys(customLaunchers),
    reporters: ['dots', 'saucelabs'],

    // Continuous Integration mode
    // if true, Karma captures browsers, runs the tests and exits
    singleRun: true,

    // Concurrency level
    // how many browser should be started simultaneous
    concurrency: Infinity,

    // Mocha
    client: {
      mocha: {
        // increase from default 2s
        timeout: 20000
      }
    },

    // Proxied paths
    proxies: {
      '/forge/prime.worker.js': '/base/lib/prime.worker.js'
    }
  });
};
