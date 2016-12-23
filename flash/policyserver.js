/**
 * Forge test Flash Policy Server.
 *
 * @author Dave Longley
 * @author David I. Lehn
 *
 * Copyright (c) 2010-2016 Digital Bazaar, Inc.
 */
const net = require('net');
const program = require('commander');

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
exports.policyServer = function(port) {
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
  server.listen(port, () => {
    console.log(prefix + 'listening: ', server.address());
  });
};

if(require.main === module) {
  program
    //.option('--host [host]',
    //  'host to bind to [localhost]')
    .option('--policy-port [port]',
      'port used to serve policy file [19945]', 19945)
    .parse(process.argv);

  exports.policyServer(program.policyPort);
}
