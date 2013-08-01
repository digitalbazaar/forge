Running the browser-based tests
===============================

    npm install
    node server.js

Then go to http://localhost:8083/.

Testing Require.js optimised version of the JavaScript
------------------------------------------------------

    npm install -g requirejs
    r.js -o build.js

You will now have a single optimised JS file at ui/test.min.js, containing the
tests and all the forge dependencies.

Now edit ui/index.html and change `data-main="test"` to `data-main="test.min"`,
then reload http://localhost:8083/.
