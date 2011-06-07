/**
 * Node.js unit tests for JSON-LD.
 *
 * @author Dave Longley
 *
 * Copyright (c) 2011 Digital Bazaar, Inc. All rights reserved.
 */
var sys = require('sys');
var forge = require('../js/forge');
var jsonld = forge.jsonld;

function TestRunner()
{
   // set up groups, add root group
   this.groups = [];
   this.group('');
};

TestRunner.prototype.group = function(name)
{
   this.groups.push(
   {
      name: name,
      tests: []
   });
};

TestRunner.prototype.ungroup = function()
{
   this.groups.pop();
};

TestRunner.prototype.test = function(name)
{
   this.groups[this.groups.length - 1].tests.push(name);
};

TestRunner.prototype.check = function(expect, result)
{
   expect = JSON.stringify(expect, null, 2);
   result = JSON.stringify(result, null, 2);
   
   var line = '';
   for(var i in this.groups)
   {
      var g = this.groups[i];
      line += (line === '') ? g.name : ('/' + g.name);
   }
   
   var g = this.groups[this.groups.length - 1];
   line += '/' + g.tests.pop();
   
   var fail = false;
   if(expect === result)
   {
      line += '... PASS';
   }
   else
   {
      line += '... FAIL';
      fail = true;
   }
   
   sys.puts(line);
   if(fail)
   {
      sys.puts('Expect: ' + expect);
      sys.puts('Result: ' + result);
   }
}

var normalize = function(tr)
{
   tr.group('normalize');
   
   (function()
   {
      tr.test('simple id');
      
      var input = {
         '@': 'http://example.org/test#example'
      };
      
      var output = jsonld.normalize(input);
      
      var expect = [{
         '@': {
            '@iri': 'http://example.org/test#example'
         }
      }];
      
      tr.check(expect, output); 
   })();
   
   (function()
   {
      tr.test('bnode');
      
      var input = {
         '@context': {
            'ex': 'http://example.org/vocab#'
         },
         'a': 'ex:Foo'
      };
      
      var output = jsonld.normalize(input);
      
      var expect = [{
         'http://www.w3.org/1999/02/22-rdf-syntax-ns#type': {
            '@iri': 'http://example.org/vocab#Foo'
         }
      }];
      
      tr.check(expect, output); 
   })();
   
   (function()
   {
      tr.test('bnode plus embed w/subject');
      
      var input = {
         '@context': {
            'ex': 'http://example.org/vocab#'
         },
         'a': 'ex:Foo',
         'ex:embed': {
            '@': 'http://example.org/test#example'
         }
      };
      
      var output = jsonld.normalize(input);
      
      var expect = [{
         'http://www.w3.org/1999/02/22-rdf-syntax-ns#type': {
            '@iri': 'http://example.org/vocab#Foo'
         },
         'http://example.org/vocab#embed': {
            '@iri': 'http://example.org/test#example'
         }
      }, {
         '@': {
            '@iri': 'http://example.org/test#example'
         }
      }];
      
      tr.check(expect, output); 
   })();
   
   (function()
   {
      tr.test('bnode embed');
      
      var input = {
         '@context': {
            'ex': 'http://example.org/vocab#'
         },
         '@': 'http://example.org/test#example',
         'a': 'ex:Foo',
         'ex:embed': {
            'a': 'ex:Bar'
         }
      };
      
      var output = jsonld.normalize(input);
      
      var expect = [{
         '@': {
            '@iri': 'http://example.org/test#example'
         },
         'http://www.w3.org/1999/02/22-rdf-syntax-ns#type': {
            '@iri': 'http://example.org/vocab#Foo'
         },
         'http://example.org/vocab#embed': {
            'http://www.w3.org/1999/02/22-rdf-syntax-ns#type': {
               '@iri': 'http://example.org/vocab#Bar'
            }
         }
      }];
      
      tr.check(expect, output); 
   })();
   
   (function()
   {
      tr.test('multiple rdf types');
      
      var input = {
         '@context': {
            'ex': 'http://example.org/vocab#'
         },
         '@': 'http://example.org/test#example',
         'a': ['ex:Foo', 'ex:Bar']
      };
      
      var output = jsonld.normalize(input);
      
      var expect = [{
         '@': {
            '@iri': 'http://example.org/test#example'
         },
         'http://www.w3.org/1999/02/22-rdf-syntax-ns#type': [{
            '@iri': 'http://example.org/vocab#Foo'
         }, {
            '@iri': 'http://example.org/vocab#Bar'
         }]
      }];
      
      tr.check(expect, output); 
   })();
   
   (function()
   {
      tr.test('coerce CURIE value');
      
      var input = {
         '@context': {
            'ex': 'http://example.org/vocab#',
            '@coerce': {
               'xsd:anyURI': 'ex:foo'
            }
         },
         '@': 'http://example.org/test#example',
         'a': 'ex:Foo',
         'ex:foo': 'ex:Bar'
      };
      
      var output = jsonld.normalize(input);
      
      var expect = [{
         '@': {
            '@iri': 'http://example.org/test#example'
         },
         'http://www.w3.org/1999/02/22-rdf-syntax-ns#type': {
            '@iri': 'http://example.org/vocab#Foo'
         },
         'http://example.org/vocab#foo': {
            '@iri': 'http://example.org/vocab#Bar'
         }
      }];
      
      tr.check(expect, output);
   })();
   
   (function()
   {
      tr.test('single subject complex');
      
      var input = {
         '@context': {
            'dc': 'http://purl.org/dc/elements/1.1/',
            'ex': 'http://example.org/vocab#',
            '@coerce': {
               'xsd:anyURI': 'ex:contains'
            }
         },
         '@': 'http://example.org/test#library',
         'ex:contains': {
            '@': 'http://example.org/test#book',
            'dc:contributor': 'Writer',
            'dc:title': 'My Book',
            'ex:contains': {
               '@': 'http://example.org/test#chapter',
               'dc:description': 'Fun',
               'dc:title': 'Chapter One'
            }
         }
      };
      
      var output = jsonld.normalize(input);
      
      var expect = [{
         '@': {
            '@iri': 'http://example.org/test#book'
         },
         'http://purl.org/dc/elements/1.1/contributor': 'Writer',
         'http://purl.org/dc/elements/1.1/title': 'My Book',
         'http://example.org/vocab#contains': {
            '@iri': 'http://example.org/test#chapter'
         },
      }, {
         '@': {
            '@iri': 'http://example.org/test#chapter'
         },
         'http://purl.org/dc/elements/1.1/description': 'Fun',
         'http://purl.org/dc/elements/1.1/title': 'Chapter One'
      }, {
         '@': {
            '@iri': 'http://example.org/test#library'
         },
         'http://example.org/vocab#contains': {
            '@iri': 'http://example.org/test#book'
         }
      }];
      
      tr.check(expect, output);
   })();
   
   (function()
   {
      tr.test('multiple subjects - complex');
      
      var input = {
         '@context': {
            'dc': 'http://purl.org/dc/elements/1.1/',
            'ex': 'http://example.org/vocab#',
            '@coerce': {
               'xsd:anyURI': ['ex:authored', 'ex:contains']
            },
         },
         '@': [{
            '@': 'http://example.org/test#chapter',
            'dc:description': 'Fun',
            'dc:title': 'Chapter One',
         }, {
            '@': 'http://example.org/test#jane',
            'ex:authored': 'http://example.org/test#chapter',
            'foaf:name': 'Jane'
         }, {
            '@': 'http://example.org/test#john',
            'foaf:name': 'John'
         }, {
            '@': 'http://example.org/test#library',
            'ex:contains': {
               '@': 'http://example.org/test#book',
               'dc:contributor': 'Writer',
               'dc:title': 'My Book',
               'ex:contains': 'http://example.org/test#chapter'
            }
         }]
      };
      
      var output = jsonld.normalize(input);
      
      var expect = [{
         '@': {
            '@iri': 'http://example.org/test#book'
         },
         'http://purl.org/dc/elements/1.1/contributor': 'Writer',
         'http://purl.org/dc/elements/1.1/title': 'My Book',
         'http://example.org/vocab#contains': {
            '@iri': 'http://example.org/test#chapter'
         },
      }, {
         '@': {
            '@iri': 'http://example.org/test#chapter'
         },
         'http://purl.org/dc/elements/1.1/description': 'Fun',
         'http://purl.org/dc/elements/1.1/title': 'Chapter One'
      }, {
         '@': {
            '@iri': 'http://example.org/test#jane'
         },
         'http://example.org/vocab#authored': {
            '@iri': 'http://example.org/test#chapter'
         },
         'http://xmlns.com/foaf/0.1/name': 'Jane'
      }, {
         '@': {
            '@iri': 'http://example.org/test#john'
         },
         'http://xmlns.com/foaf/0.1/name': 'John'
      }, {
         '@': {
            '@iri': 'http://example.org/test#library'
         },
         'http://example.org/vocab#contains': {
            '@iri': 'http://example.org/test#book'
         }
      }];
      
      tr.check(expect, output);
   })();
   
   tr.ungroup();
};

// run tests
var tr = new TestRunner();

tr.group('JSON-LD');

// FIXME: use files, read in tests (names, inputs, expects) from test
// directory, create tests, run them

normalize(tr);

tr.ungroup();
