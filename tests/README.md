Forge Tests
===========

Prepare to run tests
--------------------

    npm install

Running automated tests with Node.js
------------------------------------

    npm test

Running automated tests with PhantomJS
--------------------------------------

    npm run test-karma

Running automated tests with one or more browsers
-------------------------------------------------

    npm run test-karma -- --browsers Chrome,Firefox,PhantomJS

Running manual tests in a browser
---------------------------------

To run the unit tests in a browser a special forge build is required:

    npm run test-build

To run legacy browser based tests the main forge build is required:

    npm run build

The tests are run with a custom server that prints out the URL to use:

    npm run test-server

Running other tests
-------------------

There are some other random tests and benchmarks available.
