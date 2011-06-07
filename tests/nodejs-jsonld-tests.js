/**
 * Node.js unit tests for JSON-LD.
 *
 * @author Dave Longley
 *
 * Copyright (c) 2011 Digital Bazaar, Inc. All rights reserved.
 */
var sys = require('sys');
var fs = require('fs');
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

TestRunner.prototype.load = function(path)
{
   var tests = [];
   
   // get full path
   path = fs.realpathSync(path);
   sys.log('Reading tests from: "' + path + '"');
   
   // read each test file from the directory
   var files = fs.readdirSync(path);
   for(var i in files)
   {
      var file = path + '/' + files[i];
      sys.log('Reading test file: "' + file + '"');
      tests.push(JSON.parse(fs.readFileSync(file, 'utf8')));
   }
   
   return tests;
};

TestRunner.prototype.run = function(tests)
{
   /* Test format:
      {
         group: <optional group name>,
         tests: [{
            'name': <test name>,
            'type': <type of test>,
            'input': <input for test>,
            'expect': <expected result>,
            'context': <context for add context test type>
         }]
      }
      
      If 'group' is present, then 'tests' must be present and list all of the
      tests in the group. If 'group' is not present then 'name' must be present
      as well as 'input' and 'expect'. Groups may be embedded. The test types
      are: normalize, expand, and compact.
    */
   for(var i in tests)
   {
      var test = tests[i];
      if('group' in test)
      {
         tr.group(test.group);
         this.run(test.tests);
         tr.ungroup();
      }
      else if(!('name' in test))
      {
         throw '"group" or "name" must be specified in test file.';
      }
      else
      {
         tr.test(test.name);
         if(test.type === 'normalize')
         {
            tr.check(test.expect, jsonld.normalize(test.input));
         }
         else if(test.type === 'expand')
         {
            tr.check(test.expect, jsonld.removeContext(test.input));
         }
         else if(test.type === 'compact')
         {
            tr.check(test.expect, jsonld.addContext(test.context, test.input));
         }
         else
         {
            throw 'Unknown test type: ' + test.type;
         }
      }
   }
};

// load and run tests
var tr = new TestRunner();
tr.group('JSON-LD');
tr.run(tr.load('jsonld'));
tr.ungroup();
