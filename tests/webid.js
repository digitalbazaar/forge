/**
 * Forge Web ID Tests
 *
 * @author Dave Longley
 *
 * Copyright (c) 2010 Digital Bazaar, Inc. All rights reserved.
 */
(function($)
{
   // load flash socket pool
   window.forge.socketPool = {};
   window.forge.socketPool.ready = function()
   {
      // init forge xhr
      forge.xhr.init({
         flashId: 'socketPool',
         policyPort: 19945,
         msie: $.browser.msie,
         connections: 10,
         caCerts: [],
         verify: function(c, verified, depth, certs)
         {
            // don't care about cert verification for test
            return true;
         }
      });
   };
   swfobject.embedSWF(
      'forge/SocketPool.swf', 'socketPool', '0', '0', '9.0.0',
      false, {}, {allowscriptaccess: 'always'}, {});
})(jQuery);

jQuery(function($)
{
   var cat = 'web-id-test';
   
   // local alias
   var forge = window.forge;

   $('#create').click(function()
   {
      var bits = $('#bits')[0].value;
      var uri = $('#uri')[0].value;
      var commonName = $('#commonName')[0].value;
      console.log('generating ' + bits +
         '-bit RSA key-pair and certificate...');
      
      // function to create cert
      var createCert = function(keys)
      {
         try
         {
            var cert = forge.pki.createCertificate();
            cert.serialNumber = '01';
            cert.validity.notBefore = new Date();
            cert.validity.notAfter = new Date();
            cert.validity.notAfter.setFullYear(
               cert.validity.notBefore.getFullYear() + 1);
            var attrs = [{
               name: 'commonName',
               value: commonName
            }, {
               name: 'countryName',
               value: 'US'
            }, {
               shortName: 'ST',
               value: 'Virginia'
            }, {
               name: 'localityName',
               value: 'Blacksburg'
            }, {
               name: 'organizationName',
               value: 'Test'
            }, {
               shortName: 'OU',
               value: 'Test'
            }];
            cert.setSubject(attrs);
            cert.setIssuer(attrs);
            cert.setExtensions([{
               name: 'basicConstraints',
               cA: true
            }, {
               name: 'keyUsage',
               keyCertSign: true,
               digitalSignature: true,
               nonRepudiation: true,
               keyEncipherment: true,
               dataEncipherment: true
            }, {
               name: 'subjectAltName',
               altNames: [{
                  type: 6, // URI
                  value: uri
               }]
            }]);
            // FIXME: add subjectKeyIdentifier extension
            // FIXME: add authorityKeyIdentifier extension
            cert.publicKey = keys.publicKey;
            
            // self-sign certificate
            cert.sign(keys.privateKey);
            
            // verify certificate
            console.log('verified', cert.verify(cert));
            
            console.log('certificate:', cert);
            //console.log(
            //   forge.asn1.prettyPrint(forge.pki.certificateToAsn1(cert)));
            var keyPem = forge.pki.privateKeyToPem(keys.privateKey);
            var certPem = forge.pki.certificateToPem(cert);
            console.log(keyPem);
            console.log(certPem);
            
            console.log('storing certificate and private key...');
            try
            {
               // get flash API
               var flashApi = document.getElementById('socketPool');
               
               // get web ids collection
               var webids = forge.util.getItem(
                  flashApi, 'forge.test.webid', 'webids');
               webids = webids || {};
               
               // add web id
               webids[uri] = {
                  certificate: certPem,
                  privateKey: keyPem
               };
               
               // update web ids collection
               forge.util.setItem(
                  flashApi, 'forge.test.webid', 'webids', webids);
               
               console.log('certificate and private key stored');
               $('#show').click();
            }
            catch(ex)
            {
               console.log(ex);
            }
         }
         catch(ex)
         {
            console.error(ex, ex.message ? ex.message : '');
         }
      };
      
      // create key-generation state and function to step algorithm
      var progress = $('#progress');
      progress.html('Generating ' + bits + '-bit key-pair.');
      var state = forge.pki.rsa.createKeyPairGenerationState(bits);
      var step = function()
      {
         // step key-generation
         if(!forge.pki.rsa.stepKeyPairGenerationState(state, 1000))
         {
            progress.html(progress.html() + '.');
            setTimeout(step, 1);
         }
         // key-generation complete
         else
         {
            createCert(state.keys);
            progress.empty();
         }
      };
      
      // run key-gen algorithm
      setTimeout(step, 0);
   });

   $('#show').click(function()
   {  
      console.log('get stored web IDs...');
      try
      {
         // get flash API
         var flashApi = document.getElementById('socketPool');
         
         // get web ids collection
         var webids = forge.util.getItem(
            flashApi, 'forge.test.webid', 'webids');
         webids = webids || {};
         
         var html = '<ul>';
         var webid, cert;
         for(var key in webids)
         {
            webid = webids[key];
            cert = forge.pki.certificateFromPem(webid.certificate);
            html += '<li><p>' + key + '</p>';
            
            var attr;
            for(var n = 0; n < cert.subject.attributes.length; ++n)
            {
               attr = cert.subject.attributes[n];
               html += attr.name + ': ' + attr.value + '<br/>';
            }
            
            //html += '<p>' + webid.certificate + '</p></li>';
            html += '</li>';
         }
         if(html === '<ul>')
         {
            html = 'None';
         }
         else
         {
            html += '</ul>';
         }
         
         $('#webids').html(html);
         
         console.log('Web IDs retrieved');
      }
      catch(ex)
      {
         console.log(ex);
      }
   });
   
   $('#clear').click(function()
   {  
      console.log('clearing all web IDs...');
      try
      {
         // get flash API
         var flashApi = document.getElementById('socketPool');
         forge.util.clearItems(flashApi, 'forge.test.webid');
         $('#webids').html('None');
         console.log('Web IDs retrieved');
      }
      catch(ex)
      {
         console.log(ex);
      }
   });
   
   $('#authenticate').click(function()
   {
      console.log('doing Web ID authentication...');
      
      try
      {
         // get flash API
         var flashApi = document.getElementById('socketPool');
         
         // get web ids collection
         var webids = forge.util.getItem(
            flashApi, 'forge.test.webid', 'webids');
         webids = webids || {};
         
         var uri = $('#webid')[0].value;
         var webid = webids[uri];
         
         $.ajax(
         {
            type: 'GET',
            url: '/',
            success: function(data, textStatus, xhr)
            {
               if(data !== '')
               {
                  console.log('authentication completed');
                  console.log(data);
               }
               else
               {
                  console.log('authentication failed');
               }
            },
            error: function(xhr, textStatus, errorThrown)
            {
               console.log('authentication failed');
            },
            xhr: function()
            {
               return forge.xhr.create({
                  // FIXME: change URL
                  url: 'https://localhost:4433',
                  connections: 10,
                  caCerts: [],
                  verify: function(c, verified, depth, certs)
                  {
                     // don't care about cert verification for test
                     return true;
                  },
                  getCertificate: function(c)
                  {
                     //console.log('using cert', webid.certificate);
                     return webid.certificate;
                  },
                  getPrivateKey: function(c)
                  {
                     //console.log('using private key', webid.privateKey);
                     return webid.privateKey;
                  }
               });
            }
         });      
      }
      catch(ex)
      {
         console.log(ex);
      }
   });
});
