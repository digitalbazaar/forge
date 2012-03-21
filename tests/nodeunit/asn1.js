var forge = require("../../js/forge");

exports.testGeneralizedTimeToDate = function(test) {
   d = new Date();
   var localOffset = d.getTimezoneOffset() * 60000;

   // test local time case
   d = forge.asn1.generalizedTimeToDate('20110223123400');
   test.equal(d.getTime(), 1298464440000 + localOffset);

   d = forge.asn1.generalizedTimeToDate('20110223123400.1');
   test.equal(d.getTime(), 1298464440100 + localOffset);

   d = forge.asn1.generalizedTimeToDate('20110223123400.123');
   test.equal(d.getTime(), 1298464440123 + localOffset);

   // test utc time case
   d = forge.asn1.generalizedTimeToDate('20110223123400Z');
   test.equal(d.getTime(), 1298464440000);   // Wed Feb 23 12:34:00.000 UTC 2011

   d = forge.asn1.generalizedTimeToDate('20110223123400.1Z');
   test.equal(d.getTime(), 1298464440100);   // Wed Feb 23 12:34:00.100 UTC 2011

   d = forge.asn1.generalizedTimeToDate('20110223123400.123Z');
   test.equal(d.getTime(), 1298464440123);   // Wed Feb 23 12:34:00.123 UTC 2011

   // test positive offset
   d = forge.asn1.generalizedTimeToDate('20110223123400+0200');
   test.equal(d.getTime(), 1298457240000);   // Wed Feb 23 10:34:00.000 UTC 2011

   d = forge.asn1.generalizedTimeToDate('20110223123400.1+0200');
   test.equal(d.getTime(), 1298457240100);   // Wed Feb 23 10:34:00.100 UTC 2011

   d = forge.asn1.generalizedTimeToDate('20110223123400.123+0200');
   test.equal(d.getTime(), 1298457240123);   // Wed Feb 23 10:34:00.123 UTC 2011

   // test negative offset
   d = forge.asn1.generalizedTimeToDate('20110223123400-0200');
   test.equal(d.getTime(), 1298471640000);   // Wed Feb 23 14:34:00.000 UTC 2011

   d = forge.asn1.generalizedTimeToDate('20110223123400.1-0200');
   test.equal(d.getTime(), 1298471640100);   // Wed Feb 23 14:34:00.100 UTC 2011

   d = forge.asn1.generalizedTimeToDate('20110223123400.123-0200');
   test.equal(d.getTime(), 1298471640123);   // Wed Feb 23 14:34:00.123 UTC 2011

   test.done();
}

exports.testUtcTimeToDate = function(test) {
   d = forge.asn1.utcTimeToDate('1102231234Z');
   test.equal(d.getTime(), 1298464440000);   // Wed Feb 23 12:34:00 UTC 2011

   d = forge.asn1.utcTimeToDate('1102231234+0200');
   test.equal(d.getTime(), 1298457240000);   // Wed Feb 23 10:34:00 UTC 2011

   d = forge.asn1.utcTimeToDate('1102231234-0200');
   test.equal(d.getTime(), 1298471640000);   // Wed Feb 23 14:34:00 UTC 2011

   d = forge.asn1.utcTimeToDate('110223123456Z');
   test.equal(d.getTime(), 1298464496000);   // Wed Feb 23 12:34:56 UTC 2011

   d = forge.asn1.utcTimeToDate('110223123456+0200');
   test.equal(d.getTime(), 1298457296000);   // Wed Feb 23 10:34:56 UTC 2011

   d = forge.asn1.utcTimeToDate('110223123456-0200');
   test.equal(d.getTime(), 1298471696000);   // Wed Feb 23 14:34:56 UTC 2011

   test.done();
}
