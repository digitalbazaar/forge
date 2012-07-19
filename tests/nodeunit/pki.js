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

exports.testImportCertSha256WithRSAPSS = function(test) {
  var certPem = fs.readFileSync(__dirname + '/_files/pki_cert_sha256pss_testcert.pem', 'ascii');
  var cert = forge.pki.certificateFromPem(certPem, true);

  test.equal(cert.signatureOid, forge.pki.oids['RSASSA-PSS']);
  test.equal(cert.signatureParameters.hash.algorithmOid, forge.pki.oids['sha256']);
  test.equal(cert.signatureParameters.mgf.algorithmOid, forge.pki.oids['mgf1']);
  test.equal(cert.signatureParameters.mgf.hash.algorithmOid, forge.pki.oids['sha256']);
  test.equal(cert.siginfo.algorithmOid, forge.pki.oids['RSASSA-PSS']);
  test.equal(cert.siginfo.parameters.hash.algorithmOid, forge.pki.oids['sha256']);
  test.equal(cert.siginfo.parameters.mgf.algorithmOid, forge.pki.oids['mgf1']);
  test.equal(cert.siginfo.parameters.mgf.hash.algorithmOid, forge.pki.oids['sha256']);
  test.done();
};

exports.testVerifySignatureSha256WithRSAPSS = function(test) {
  var certPem = fs.readFileSync(__dirname + '/_files/pki_cert_sha256pss_testcert.pem', 'ascii');
  var issuerPem = fs.readFileSync(__dirname + '/_files/pki_cert_sha256pss_issuer.pem', 'ascii');

  var cert = forge.pki.certificateFromPem(certPem, true);
  var issuer = forge.pki.certificateFromPem(issuerPem);

  test.equal(issuer.verify(cert), true);
  test.done();
};

exports.testReexportCertSha256WithRSAPSS = function(test) {
  var certPem = fs.readFileSync(__dirname + '/_files/pki_cert_sha256pss_testcert.pem', 'ascii');
  var cert = forge.pki.certificateFromPem(certPem, true);
  var certExportPem = forge.pki.certificateToPem(cert, 64);
  test.equals(certExportPem, certPem);
  test.done();
};
