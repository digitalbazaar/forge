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
      
      input = {
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
      tr.test('no subject identifier');
      
      input = {
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
      tr.test('no subject identifier plus embed w/subject');
      
      input = {
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
      },
      {
         '@': {
            '@iri': 'http://example.org/test#example'
         }
      }];
      
      tr.check(expect, output); 
   })();
   
   tr.ungroup();
};

// run tests
var tr = new TestRunner();

tr.group('JSON-LD');

normalize(tr);

tr.ungroup();
