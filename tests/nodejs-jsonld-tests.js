/**
 * Node.js unit tests for JSON-LD.
 *
 * @author Dave Longley
 *
 * Copyright (c) 2011 Digital Bazaar, Inc. All rights reserved.
 */
var sys = require('sys');
var fs = require('fs');
var path = require('path');
var forge = require('../js/forge');
var jsonld = forge.jsonld;

var _sortKeys = function(obj)
{
   var rval;
   
   if(obj === null)
   {
      rval = null;
   }
   else if(obj.constructor === Array)
   {
      rval = [];
      for(var i in obj)
      {
         rval[i] = _sortKeys(obj[i]);
      }
   }
   else if(obj.constructor === Object)
   {
      rval = {};
      var keys = Object.keys(obj);
      keys.sort();
      for(var i in keys)
      {
         rval[keys[i]] = _sortKeys(obj[keys[i]]);
      }
   }
   else
   {
      rval = obj;
   }
   
   return rval;
};

var _stringifySorted = function(obj)
{
   return JSON.stringify(_sortKeys(obj), null, 3);
};

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
   expect = _stringifySorted(expect);
   result = _stringifySorted(result);
   
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
      
      // FIXME: remove me
      throw 'FAIL';
   }
}

TestRunner.prototype.load = function(filepath)
{
   var tests = [];
   
   // get full path
   filepath = fs.realpathSync(filepath);
   sys.log('Reading tests from: "' + filepath + '"');
   
   // read each test file from the directory
   var files = fs.readdirSync(filepath);
   for(var i in files)
   {
      var file = path.join(filepath, files[i]);
      if(path.extname(file) == '.json')
      {
         sys.log('Reading test file: "' + file + '"');
         tests.push(JSON.parse(fs.readFileSync(file, 'utf8')));
      }
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
            'context': <context for add context test type>,
            'frame': <frame for frame test type>,
            'expect': <expected result>,
         }]
      }
      
      If 'group' is present, then 'tests' must be present and list all of the
      tests in the group. If 'group' is not present then 'name' must be present
      as well as 'input' and 'expect'. Groups may be embedded.
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
         var input = test.input;
         if(test.type.constructor !== Array)
         {
            test.type = [test.type];
         }
         for(var t in test.type)
         {
            var type = test.type[t];
            if(type === 'normalize')
            {
               input = jsonld.normalize(input);
            }
            else if(type === 'expand')
            {
               input = jsonld.removeContext(input);
            }
            else if(type === 'compact')
            {
               input = jsonld.addContext(test.context, input);
            }
            else if(type === 'change')
            {
               input = jsonld.changeContext(test.context, input);
            }
            else if(type === 'compare')
            {
               var result = [];
               var tmp = [];
               for(var n in input)
               {
                  result.push(jsonld.normalize(input[n]));
                  tmp.push(test.expect);
               }
               input = result;
               test.expect = tmp;
            }
            else if(type === 'frame')
            {
               input = jsonld.frame(input, test.frame);
            }
            else
            {
               throw 'Unknown test type: ' + type;
            }
         }
         tr.check(test.expect, input);
      }
   }
};

// load and run tests
var tr = new TestRunner();
tr.group('JSON-LD');
tr.run(tr.load('jsonld'));
tr.ungroup();
