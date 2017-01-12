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
const path = require('path');
const program = require('commander');
const policyServer = require('../flash/policyserver');

program
  //.option('--host [host]',
  //  'host to bind to [localhost]')
  .option('--http-port [port]',
    'port for HTTP [19400]', 19400)
  .option('--https-port [port]',
    'port for HTTPS [19443]', 19443)
  .option('--policy-port [port]',
    'port for policy files [19945]', 19945)
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
    express.static(path.join(
      __dirname, '..', 'flash', 'swf', 'SocketPool.swf')));
  app.use('/forge/prime.worker.js',
    express.static(path.join(__dirname, '..', 'dist', 'prime.worker.js')));
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

  const tlsSessionStore = {};
  let httpsServer = https
    .createServer(httpsOptions, app)
    .on('newSession', (id, data, cb) => {
      //console.log('[https-server] new session: ' + id.toString('hex'));
      tlsSessionStore[id.toString('hex')] = data;
      cb();
    })
    .on('resumeSession', (id, cb) => {
      //console.log('[https-server] resume session: ' + id.toString('hex'));
      cb(null, tlsSessionStore[id.toString('hex')] || null);
    });
  httpsServer.listen(program.httpsPort, () => {
    console.log(
      '[https-server] listening: https://localhost:' +
      httpsServer.address().port + '/');
  });
}

// start servers
contentServer();
policyServer.policyServer(program.policyPort);
