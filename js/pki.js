/**
 * Javascript implementation of a basic Public Key Infrastructure, including
 * support for RSA public and private keys.
 *
 * @author Dave Longley
 *
 * Copyright (c) 2010-2013 Digital Bazaar, Inc.
 */
var pem = require("./pem");
var util = require("./util");
var asn1 = require("./asn1");
var x509 = require("./x509");
var rsa = require("./rsa");
var pbe = require("./pbe");

/* Public Key Infrastructure (PKI) implementation. */
var pki = {oids: require("./oids")};

module.exports = pki;

/**
 * NOTE: THIS METHOD IS DEPRECATED. Use pem.decode() instead.
 *
 * Converts PEM-formatted data to DER.
 *
 * @param pem the PEM-formatted data.
 *
 * @return the DER-formatted data.
 */
pki.pemToDer = function(passed_pem) {
  var msg = pem.decode(passed_pem)[0];
  if(msg.procType && msg.procType.type === 'ENCRYPTED') {
    throw new Error('Could not convert PEM to DER; PEM is encrypted.');
  }
  return util.createBuffer(msg.body);
};

/**
 * Converts an RSA private key from PEM format.
 *
 * @param pem the PEM-formatted private key.
 *
 * @return the private key.
 */
pki.privateKeyFromPem = function(passed_pem) {
  var msg = pem.decode(passed_pem)[0];

  if(msg.type !== 'PRIVATE KEY' && msg.type !== 'RSA PRIVATE KEY') {
    var error = new Error('Could not convert private key from PEM; PEM ' +
      'header type is not "PRIVATE KEY" or "RSA PRIVATE KEY".');
    error.headerType = msg.type;
    throw error;
  }
  if(msg.procType && msg.procType.type === 'ENCRYPTED') {
    throw new Error('Could not convert private key from PEM; PEM is encrypted.');
  }

  // convert DER to ASN.1 object
  var obj = asn1.fromDer(msg.body);

  return pki.privateKeyFromAsn1(obj);
};

/**
 * Converts an RSA private key to PEM format.
 *
 * @param key the private key.
 * @param maxline the maximum characters per line, defaults to 64.
 *
 * @return the PEM-formatted private key.
 */
pki.privateKeyToPem = function(key, maxline) {
  // convert to ASN.1, then DER, then PEM-encode
  var msg = {
    type: 'RSA PRIVATE KEY',
    body: asn1.toDer(rsa.privateKeyToAsn1(key)).getBytes()
  };
  return pem.encode(msg, {maxline: maxline});
};

/**
 * Converts a PrivateKeyInfo to PEM format.
 *
 * @param pki the PrivateKeyInfo.
 * @param maxline the maximum characters per line, defaults to 64.
 *
 * @return the PEM-formatted private key.
 */
pki.privateKeyInfoToPem = function(pki, maxline) {
  // convert to DER, then PEM-encode
  var msg = {
    type: 'PRIVATE KEY',
    body: asn1.toDer(pki).getBytes()
  };
  return pem.encode(msg, {maxline: maxline});
};

["decryptRsaPrivateKey", "encryptRsaPrivateKey", "encryptPrivateKeyInfo", "decryptPrivateKeyInfo"].forEach(function(i) {
  pki[i] = pbe[i];
});

["getPublicKeyFingerprint", "certificateError", "verifyCertificateChain", "createCaStore", "certificateToPem", "createCertificate", "publicKeyToPem", "publicKeyFromPem", "createCertificationRequest", "certificationRequestToPem", "certificationRequestFromPem", "certificateFromPem", "certificateToAsn1", "RDNAttributesAsArray", "distinguishedNameToAsn1", "certificateFromAsn1"].forEach(function(i) {
  pki[i] = x509[i];
});

["setRsaPrivateKey", "setRsaPublicKey", "setPublicKey", "wrapRsaPrivateKey", "privateKeyFromAsn1", "privateKeyToAsn1", "privateKeyToRSAPrivateKey", "publicKeyFromAsn1", "publicKeyToAsn1", "publicKeyToSubjectPublicKeyInfo", "publicKeyToRSAPublicKey"].forEach(function(i) {
  pki[i] = rsa[i];
});

pki.rsa = rsa;
