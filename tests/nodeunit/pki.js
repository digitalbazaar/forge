var forge = require('../../js/forge');
var fs = require('fs');

exports.testVerifySignatureSha1WithRSA = function(test) {
  var certPem = fs.readFileSync(__dirname + '/_files/pki_cert_sha1_wwwgooglede.pem', 'ascii');
  var issuerPem = fs.readFileSync(__dirname + '/_files/pki_cert_sha1_googleca.pem', 'ascii');

  var cert = forge.pki.certificateFromPem(certPem, true);
  var issuer = forge.pki.certificateFromPem(issuerPem);

  test.equal(issuer.verify(cert), true);
  test.done();
};

exports.testVerifySignatureSha256WithRSA = function(test) {
  var certPem = fs.readFileSync(__dirname + '/_files/pki_cert_sha256_testcert.pem', 'ascii');
  var issuerPem = fs.readFileSync(__dirname + '/_files/pki_cert_sha256_issuer.pem', 'ascii');

  var cert = forge.pki.certificateFromPem(certPem, true);
  var issuer = forge.pki.certificateFromPem(issuerPem);

  test.equal(issuer.verify(cert), true);
  test.done();
};
