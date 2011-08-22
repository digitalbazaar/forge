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
var jsonld = require('../js/jsonld');

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

var _stringifySorted = function(obj, indent)
{
   return JSON.stringify(_sortKeys(obj), null, indent);
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
      tests: [],
      count: 1
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

TestRunner.prototype.check = function(expect, result, indent)
{
   if(typeof(indent) === 'undefined')
   {
      indent = 0;
   }
   
   // sort and use given indent level
   expect = _stringifySorted(expect, indent);
   result = _stringifySorted(result, indent);
   
   var line = '';
   for(var i in this.groups)
   {
      var g = this.groups[i];
      line += (line === '') ? g.name : ('/' + g.name);
   }
   
   var g = this.groups[this.groups.length - 1];
   if(g.name !== '')
   {
      var count = '' + g.count;
      var end = 4 - count.length;
      for(var i = 0; i < end; ++i)
      {
         count = '0' + count;
      }
      line += ' ' + count;
      ++g.count;
   }
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
      
      /*
      sys.puts('Legible Expect: ' +
         JSON.stringify(JSON.parse(expect), null, 2));
      sys.puts('Legible Result: ' +
         JSON.stringify(JSON.parse(result), null, 2));*/
      
      // FIXME: remove me
      throw 'FAIL';
   }
}

TestRunner.prototype.load = function(filepath)
{
   var tests = [];
   
   // get full path
   filepath = fs.realpathSync(filepath);
   sys.log('Reading test files from: "' + filepath + '"');
   
   // read each test file from the directory
   var files = fs.readdirSync(filepath);
   for(var i in files)
   {
      var file = path.join(filepath, files[i]);
      if(path.extname(file) == '.test')
      {
         sys.log('Reading test file: "' + file + '"');
         
         try
         {
            var test = JSON.parse(fs.readFileSync(file, 'utf8'));
         }
         catch(e)
         {
            sys.log('Exception while parsing file: ' + file);
            throw e;
         }
         
         if(typeof(test.filepath) === 'undefined')
         {
            test.filepath = filepath;
         }
         tests.push(test);
      }
   }
   
   sys.log(tests.length + ' test file(s) read');
   
   return tests;
};

/**
 * Reads test JSON files.
 * 
 * @param file the file to read.
 * @param filepath the test filepath.
 * 
 * @return the read JSON.
 */
var _readTestJson = function(file, filepath)
{
   var rval;
   
   try
   {
      file = path.join(filepath, file);
      rval = JSON.parse(fs.readFileSync(file, 'utf8'));
   }
   catch(e)
   {
      sys.log('Exception while parsing file: ' + file);
      throw e;
   }
   
   return rval;
};

TestRunner.prototype.run = function(tests, filepath)
{
   /* Test format:
      {
         group: <optional group name>,
         tests: [{
            'name': <test name>,
            'type': <type of test>,
            'input': <input file for test>,
            'context': <context file for add context test type>,
            'frame': <frame file for frame test type>,
            'expect': <expected result file>,
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
         this.group(test.group);
         this.run(test.tests, test.filepath);
         this.ungroup();
      }
      else if(!('name' in test))
      {
         throw '"group" or "name" must be specified in test file.';
      }
      else
      {
         this.test(test.name);
         
         // use parent test filepath as necessary
         if(typeof(test.filepath) === 'undefined') 
         {
            test.filepath = filepath;
         }
         
         // read test files
         var input = _readTestJson(test.input, test.filepath);
         test.expect = _readTestJson(test.expect, test.filepath);
         if(test.context)
         {
            test.context = _readTestJson(test.context, test.filepath);
         }
         if(test.frame)
         {
            test.frame = _readTestJson(test.frame, test.filepath);
         }
         
         // perform test
         var type = test.type;
         if(type === 'normalize')
         {
            input = jsonld.normalize(input);
         }
         else if(type === 'expand')
         {
            input = jsonld.expand(input);
         }
         else if(type === 'compact')
         {
            input = jsonld.compact(test.context, input);
         }
         else if(type === 'frame')
         {
            input = jsonld.frame(input, test.frame);
         }
         else
         {
            throw 'Unknown test type: ' + type;
         }
         
         // check results (only indent output on non-normalize tests)
         this.check(test.expect, input, (test.type === 'normalize') ? 0 : 3);
      }
   }
};

// load and run tests
try
{
   var tr = new TestRunner();
   tr.group('JSON-LD');
   tr.run(tr.load('jsonld'));
   tr.ungroup();
   sys.log('All tests complete.');
}
catch(e)
{
   if(e.constructor === Exception && 'stack' in e)
   {
      sys.puts(e.stack);
      delete e.stack;
   }
   sys.puts('Exception: ' + JSON.stringify(e, null, 2));
}
