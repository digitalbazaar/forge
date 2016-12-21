/**
 * Forge test server.
 *
 * @author Dave Longley
 * @author David I. Lehn
 *
 * Copyright (c) 2010-2016 Digital Bazaar, Inc.
 */
const express = require('express');
const fs = require('fs');
const http = require('http');
const https = require('https');
const net = require('net');
const path = require('path');
const program = require('commander');

program
  //.option('--host [host]',
  //  'host to bind to [localhost]')
  .option('--http-port [port]',
    'port to bind to HTTP [19400]', 19400)
  .option('--https-port [port]',
    'port to bind to HTTPS [19443]', 19443)
  .option('--policy-port [port]',
    'port used to serve policy file [19945]', 19945)
  .parse(process.argv);

function contentServer(callback) {
  let app = express();

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

  const httpsOptions = {
    key: fs.readFileSync(path.join(__dirname, 'server.key')),
    cert: fs.readFileSync(path.join(__dirname, 'server.crt')),
    sessionIdContext: 'forgetest'
  };

  let httpServer = http
    .createServer(app)
    .listen(program.httpPort, () => {
      console.log(
        '[http-server] listening: http://localhost:' +
        httpServer.address().port + '/');
    });
  let httpsServer = https
    .createServer(httpsOptions, app)
    .listen(program.httpsPort, () => {
      console.log(
        '[https-server] listening: https://localhost:' +
        httpsServer.address().port + '/');
    });
};

// The policy file
// NOTE: This format is very strict. Edit with care.
let policyFile =
  '<?xml version="1.0"?>' +
  '<!DOCTYPE cross-domain-policy' +
  ' SYSTEM "http://www.adobe.com/xml/dtds/cross-domain-policy.dtd">' +
  '<cross-domain-policy>' +
  '<allow-access-from domain="*" to-ports="*"/>' +
  '</cross-domain-policy>\0';

// Simple non-robust policy file server.
// Looks for a request string and returns the policy file.
function policyServer(callback) {
  let prefix = '[policy-server] ';
  let server = net.createServer((socket) => {
    let remoteAddress = socket.remoteAddress + ':' + socket.remotePort;
    console.log(prefix + 'new client connection from %s', remoteAddress);

    // deal with strings
    socket.setEncoding('utf8');

    socket.on('data', (d) => {
      if(d.indexOf('<policy-file-request/>') === 0) {
        console.log(prefix + 'policy file request from: %s', remoteAddress);
        socket.write(policyFile);
      } else {
        console.log(prefix + 'junk request from %s: %j', remoteAddress, d);
      }
    });
    socket.once('close', () => {
      console.log(prefix + 'connection from %s closed', remoteAddress);
    });
    socket.on('error', (err) => {
      console.error(
        prefix + 'connection %s error: %s', remoteAddress, err.message);
    });
  }).on('error', (err) => {
    throw err;
  });
  server.listen(program.policyPort, () => {
    console.log(prefix + 'listening: ', server.address());
  });
}

contentServer();
policyServer();
