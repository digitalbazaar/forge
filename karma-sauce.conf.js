/*!
 * Karma Sauce Labs configuration
 *
 * `SAUCE_USERNAME` and `SAUCE_ACCESS_KEY` environmental variables should
 * be set. For configuration details, see:
 * https://github.com/karma-runner/karma-sauce-launcher
 */

var baseConfig = require('./karma.conf');

module.exports = function(config) {
  // load base forge karma config
  baseConfig(config);

  // Define an unlimited number of browser/OS combinations here. Sauce Labs
  // will manage concurrency based on user's account restrictions.
  // Platform Configurator Tool:
  // https://wiki.saucelabs.com/display/DOCS/Platform+Configurator#/
  var sauceLabsCustomLaunchers = {
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
    sauceLabs: {
      testName: 'Forge Unit Tests',
      startConnect: true
    },
    captureTimeout: 180000,

    // merge SauceLabs launchers
    customLaunchers: sauceLabsCustomLaunchers,

    // default to only SauceLabs launchers
    browsers: Object.keys(sauceLabsCustomLaunchers),

    reporters: ['dots', 'saucelabs']
  });
};
