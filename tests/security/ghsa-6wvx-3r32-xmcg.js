/*
 * Regression Test for GHSA-6wvx-3r32-xmcg
 * Verifies that cookies from a server's Set-Cookie headers can't add or
 * delete properties of Object.prototype or Object in forge.http.
 */
var assert = require('assert');
var forge = require('../../lib/forge');
require('../../lib/log');
require('../../lib/tls');
require('../../lib/http');
var util = require('../../lib/util');

describe('GHSA-6wvx-3r32-xmcg Security Patch', function() {
  var http = forge.http;
  var saved = {};

  // there is no socket transport here, so stub it
  var socketPool = {
    createSocket: function() {
      return {};
    }
  };

  function createClient(url) {
    return http.createClient(
      {url: url, socketPool: socketPool, persistCookies: false});
  }

  // set the cookies of a server response on the client
  function receive(client, setCookie) {
    var response = http.createResponse();
    var buffer = util.createBuffer();
    buffer.putBytes(
      'HTTP/1.1 200 OK\r\nSet-Cookie: ' + setCookie + '\r\n\r\n');
    response.readHeader(buffer);
    return response.getCookies().map(function(cookie) {
      return client.setCookie(cookie);
    });
  }

  before(function() {
    // http.createClient() needs the URL global (Node.js 10+)
    if(typeof URL === 'undefined') {
      this.skip();
    }
  });

  beforeEach(function() {
    saved.wrapSocket = forge.tls.wrapSocket;
    saved.debug = forge.log.debug;
    saved.toLocaleString = Object.getOwnPropertyDescriptor(
      Object.prototype, 'toLocaleString');
    forge.tls.wrapSocket = function() {
      return {};
    };
    forge.log.debug = function() {};
  });

  afterEach(function() {
    forge.tls.wrapSocket = saved.wrapSocket;
    forge.log.debug = saved.debug;
    // undo any changes so a failure doesn't affect other tests
    Object.defineProperty(
      Object.prototype, 'toLocaleString', saved.toLocaleString);
    delete Object.prototype.polluted;
    delete Object.polluted;
  });

  it('should not set Object.prototype properties', function() {
    var client = createClient('https://example.com');
    assert.deepEqual(
      receive(client, '__proto__=evil; path=polluted'), [false]);
    assert.equal(Object.prototype.hasOwnProperty('polluted'), false);
    assert.equal(({}).polluted, undefined);
  });

  it('should not set Object properties', function() {
    var client = createClient('https://example.com');
    assert.deepEqual(
      receive(client, 'constructor=evil; path=polluted'), [true]);
    assert.equal(Object.hasOwnProperty('polluted'), false);
    assert.equal(client.getCookie('constructor').value, 'evil');
  });

  it('should not delete Object.prototype properties', function() {
    ['https://example.com', 'http://example.com'].forEach(function(url) {
      var client = createClient(url);
      assert.deepEqual(
        receive(client, '__proto__=; path=toLocaleString'), [false]);
      assert.equal(typeof Object.prototype.toLocaleString, 'function');
    });
  });

  it('should still set and remove normal cookies', function() {
    var client = createClient('https://example.com');
    assert.deepEqual(receive(client, 'session=abc; path=/'), [true]);
    assert.equal(client.getCookie('session').value, 'abc');
    assert.equal(client.getCookie('session', '/').value, 'abc');
    assert.deepEqual(receive(client, 'session=; path=/'), [true]);
    assert.equal(client.getCookie('session'), null);
  });
});
