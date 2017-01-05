// test support

// true if running in PhantomJS
exports.isPhantomJS =
  (typeof navigator !== 'undefined' && navigator.userAgent) ?
  navigator.userAgent.indexOf('PhantomJS') !== -1 :
  false;
