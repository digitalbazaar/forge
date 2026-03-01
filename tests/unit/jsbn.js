var ASSERT = require('assert');

(function() {
  if(typeof process === 'undefined' ||
    !process.versions || !process.versions.node) {
    return;
  }

  var moduleRequire = module.require ? module.require.bind(module) : require;
  var PATH = moduleRequire('path');
  var spawnSync = moduleRequire('child_process').spawnSync;

  describe('jsbn', function() {
    it('should return 0 for BigInteger(0).modInverse(3) without hanging', function() {
      var script = [
        'var JSBN = require("./lib/jsbn");',
        'var BigInteger = JSBN.BigInteger;',
        'var zero = new BigInteger("0", 10);',
        'var mod = new BigInteger("3", 10);',
        'var inv = zero.modInverse(mod);',
        'process.stdout.write(inv.toString());'
      ].join('\n');

      var result = spawnSync(process.execPath, ['-e', script], {
        cwd: PATH.join(__dirname, '../..'),
        encoding: 'utf8',
        timeout: 2000
      });

      if(result.error) {
        if(result.error.code === 'EPERM') {
          this.skip();
          return;
        }
        if(result.error.code === 'ETIMEDOUT') {
          ASSERT.fail('BigInteger(0).modInverse(3) timed out.');
        }
        throw result.error;
      }

      ASSERT.equal(result.status, 0, result.stderr);
      ASSERT.equal(result.stdout, '0');
    });
  });
})();
