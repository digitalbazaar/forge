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

TestRunner.prototype.check = function(expect, result, sort)
{
   if(typeof(sort) === 'undefined')
   {
      sort = true;
   }
   
   if(sort)
   {
      // sort and use whitespace
      expect = _stringifySorted(expect);
      result = _stringifySorted(result);
   }
   else
   {
      // do not sort or use whitespace
      expect = JSON.stringify(expect);
      result = JSON.stringify(result);
   }
   
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
   sys.log('Reading test files from: "' + filepath + '"');
   
   // read each test file from the directory
   var files = fs.readdirSync(filepath);
   for(var i in files)
   {
      var file = path.join(filepath, files[i]);
      if(path.extname(file) == '.test')
      {
         sys.log('Reading test file: "' + file + '"');
         var test = JSON.parse(fs.readFileSync(file, 'utf8'));
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
 * @param files the files to read.
 * @param filepath the test filepath.
 * 
 * @return the read JSON.
 */
var _readTestJson = function(files, filepath)
{
   var file = path.join(filepath, files);
   return JSON.parse(fs.readFileSync(file, 'utf8'));
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
         tr.group(test.group);
         this.run(test.tests, test.filepath);
         tr.ungroup();
      }
      else if(!('name' in test))
      {
         throw '"group" or "name" must be specified in test file.';
      }
      else
      {
         tr.test(test.name);
         
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
            input = jsonld.removeContext(input);
         }
         else if(type === 'compact')
         {
            input = jsonld.addContext(test.context, input);
         }
         else if(type === 'frame')
         {
            input = jsonld.frame(input, test.frame);
         }
         else
         {
            throw 'Unknown test type: ' + type;
         }
         
         // check results (only sort output on non-normalize tests)
         tr.check(test.expect, input, test.type !== 'normalize');
      }
   }
};

// load and run tests
var tr = new TestRunner();
tr.group('JSON-LD');
tr.run(tr.load('jsonld'));
tr.ungroup();
