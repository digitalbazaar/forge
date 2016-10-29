/**
 * Forge Issue 428 Tests
 *
 * @author Dave Longley
 *
 * Copyright (c) 2009-2012 Digital Bazaar, Inc. All rights reserved.
 */
jQuery(function($)
{
   // logging category
   var cat = 'forge.tests.common';

   // local alias
   var forge = window.forge;

   var tests = [];
   var passed = 0;
   var failed = 0;
   var iterationTests = [];
   var stop = false;

   var init = function()
   {
      passed = failed = 0;
      $('.ready,.testing,.pass,.fail')
         .removeClass('ready testing pass fail');
      $('#status')
         .text('Ready.')
         .addClass('ready');
      $('#total').text(tests.length);
      $('#pass').text(passed);
      $('#fail').text(failed);
      $('.expect').empty();
      $('.result').empty();
      $('.time').empty();
      $('.timePer').empty();
      $('#start').attr('disabled', '');
      $('#stop').attr('disabled', 'true');
      stop = false;
   };

   var doIteration = function() {
     $.each(iterationTests, function(i, test) {
       if(test.run) {
         test.loop();
       }
     });
     if(!stop) {
       setTimeout(doIteration, 0);
     }
   };

   var start = function()
   {
      $('#start').attr('disabled', 'true');
      $('#stop').attr('disabled', '');
      // meta! use tasks to run the task tests
      forge.task.start({
         type: 'test',
         run: function(task) {
            task.next('starting', function(task) {
               forge.log.debug(cat, 'start');
               $('#status')
                  .text('Testing...')
                  .addClass('testing')
                  .removeClass('idle');
            });
            $.each(tests, function(i, test) {
               task.next('test', function(task) {
                  var title = $('li:first', test.container);
                  title.addClass('testing');
                  test.run(task, test);
                  setTimeout(doIteration, 0);
               });
               task.next('test', function(task) {
                  $('li:first', test.container).removeClass('testing');
               });
            });
            task.next('success', function(task) {
               forge.log.debug(cat, 'done');
               if(failed === 0) {
                  $('#status')
                     .text('PASS')
                     .addClass('pass')
                     .removeClass('testing');
               } else {
                  // FIXME: should just be hitting failure() below
                  $('#status')
                     .text('FAIL')
                     .addClass('fail')
                     .removeClass('testing');
               }
            });
         },
         failure: function() {
            $('#status')
               .text('FAIL')
               .addClass('fail')
               .removeClass('testing');
         }
      });
   };

   $('#start').click(function() {
      start();
   });

   $('#stop').click(function() {
      stop = true;
   });

   $('#reset').click(function() {
      init();
   });

   var addTest = function(name, run)
   {
      var container = $('<ul><li>Test ' + name + '</li><ul/></ul>');
      var iterations = $('<li>Iterations: <span class="iterations"/></li>');
      var changes = $('<li>Changes: <span class="changes"/></li>');
      var expect = $('<li>Expect: <span class="expect"/></li>');
      var result = $('<li>Result: <span class="result"/></li>');
      var time = $('<li>Time: <span class="time"/></li>');
      var timePer = $('<li>Time Per Iteration: <span class="timePer"/></li>');
      $('ul', container)
         .append(iterations)
         .append(changes)
         .append(expect)
         .append(result)
         .append(time)
         .append(timePer);
      $('#tests').append(container);
      var test = {
         container: container,
         startTime: null,
         run: function(task, test) {
            test.startTime = new Date();
            run(task, test);
         },
         expect: $('span', expect),
         result: $('span', result),
         check: function(iterations) {
            var e = test.expect.text();
            var r = test.result.text();
            (e == r) ? test.pass(iterations) : test.fail(iterations);
         },
         iterations: function(iterations) {
            $('span.iterations', container).html(iterations);
         },
         changes: function(changes) {
            $('span.changes', container).html(changes);
         },
         pass: function(iterations) {
            var dt = new Date() - test.startTime;
            if(!iterations)
            {
               iterations = 1;
            }
            var dti = (dt / iterations);
            passed += 1;
            $('#pass').text(passed);
            $('li:first', container).addClass('pass');
            $('span.time', container).html(dt + 'ms');
            $('span.timePer', container).html(dti + 'ms');
         },
         fail: function(iterations) {
            var dt = new Date() - test.startTime;
            if(!iterations)
            {
               iterations = 1;
            }
            var dti = (dt / iterations);
            failed += 1;
            $('#fail').text(failed);
            $('li:first', container).addClass('fail');
            $('span.time', container).html(dt + 'ms');
            $('span.timePer', container).html(dti + 'ms');
         }
      };
      tests.push(test);
   };

   $.each(['md5','sha1','sha256','sha384','sha512'], function(i, hashId) {
     addTest(hashId, function(task, test)
     {
       var hashAttempt = 0;
       var hashValues = [];
       var testBytes = [];
       var hashUpdates = parseInt($('#hash_updates')[0].value);
       // generate random test bytes
       for(var i = 0; i < hashUpdates; ++i) {
         testBytes.push(String.fromCharCode(Math.floor(Math.random() * 256)));
       }
       iterationTests.push({
         run: true,
         loop: function() {
           if($('#do_hash_' + hashId)[0].checked) {
             hashAttempt++;
             test.iterations(hashAttempt);
             test.changes(hashValues.length);
             var hash = forge[hashId].create();
             hash.start();
             for(var i = 0; i < hashUpdates; ++i) {
               hash.update(testBytes[i]);
             }
             var hex = forge.util.bytesToHex(hash.digest().getBytes());
             if(hashValues.length === 0) {
               hashValues.push([hashAttempt, hex]);
               test.expect.html(JSON.stringify(hashValues));
               test.result.html(JSON.stringify(hashValues));
             } else {
               if(hashValues[hashValues.length - 1][1] !== hex) {
                 hashValues.push([hashAttempt, hex]);
                 test.result.html(JSON.stringify(hashValues));
                 test.fail(hashAttempt);
               }
             }
             if(stop) {
               test.check(hashAttempt);
             }
           }
         }
       });
     });
   });

   $.each(['md5','sha1','sha256','sha384','sha512'], function(i, hashId) {
     addTest(hashId + ' pbkdf2', function(task, test)
     {
       var forge_hash = function(message) {
         var digester = forge.md[hashId].create();
         digester.start();
         digester.update(message);
         return digester.digest().getBytes();
       };
       var hashAttempt = 0;
       var hashValues = [];
       var testBytes = [];
       var hashUpdates = parseInt($('#hash_updates')[0].value);
       // generate random test bytes
       for(var i = 0; i < hashUpdates; ++i) {
         testBytes.push(String.fromCharCode(Math.floor(Math.random() * 256)));
       }
       var salt = forge_hash(testBytes);
       var password = 'password';
       var rounds = parseInt($('#pbkdf2_rounds')[0].value);
       iterationTests.push({
         run: true,
         loop: function() {
           if($('#do_pbkdf2_' + hashId)[0].checked) {
             hashAttempt++;
             test.iterations(hashAttempt);
             test.changes(hashValues.length);
             var derive = forge.pkcs5.pbkdf2('password', salt, rounds, 16, hashId);
             var hex = forge.util.bytesToHex(derive);
             if(hashValues.length === 0) {
               hashValues.push([hashAttempt, hex]);
               test.expect.html(JSON.stringify(hashValues));
               test.result.html(JSON.stringify(hashValues));
             } else {
               if(hashValues[hashValues.length - 1][1] !== hex) {
                 hashValues.push([hashAttempt, hex]);
                 test.result.html(JSON.stringify(hashValues));
                 test.fail(hashAttempt);
               }
             }
             if(stop) {
               test.check(hashAttempt);
             }
           }
         }
       });
     });
   });

   init();
});
