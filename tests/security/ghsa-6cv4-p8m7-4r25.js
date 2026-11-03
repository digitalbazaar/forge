/*
 * Regression Test for GHSA-6cv4-p8m7-4r25
 * Verifies that forge.http trims response header and Set-Cookie values in
 * linear time.
 */
var assert = require('assert');
var forge = require('../../lib/forge');
require('../../lib/http');
var util = require('../../lib/util');

describe('GHSA-6cv4-p8m7-4r25 Security Patch', function() {
  var http = forge.http;

  // the previous regular expression took minutes on each input below
  var WHITESPACE = new Array(256 * 1024 + 1).join('\t ');

  function readHeader(header) {
    var response = http.createResponse();
    var buffer = util.createBuffer();
    buffer.putBytes('HTTP/1.1 200 OK\r\n' + header + '\r\n\r\n');
    assert.equal(response.readHeader(buffer), true);
    return response;
  }

  it('should trim a header value with a long whitespace run', function() {
    var response = readHeader('X-Test: a' + WHITESPACE + 'b' + WHITESPACE);
    assert.equal(response.getField('X-Test'), 'a' + WHITESPACE + 'b');
  });

  it('should trim a cookie value with a long whitespace run', function() {
    var response = readHeader('Set-Cookie: a=b' + WHITESPACE + 'c; path=/');
    var cookies = response.getCookies();
    assert.equal(cookies.length, 1);
    assert.equal(cookies[0].name, 'a');
    assert.equal(cookies[0].value, 'b' + WHITESPACE + 'c');
  });

  it('should still trim header and cookie values', function() {
    var response = readHeader(
      'X-Test: \t a  b  \t\r\nSet-Cookie:  name = value ; path=/');
    assert.equal(response.getField('X-Test'), 'a  b');
    var cookies = response.getCookies();
    assert.equal(cookies[0].name, 'name');
    assert.equal(cookies[0].value, 'value');
    assert.equal(cookies[0].path, '/');
  });
});
