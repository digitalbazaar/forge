browserify-forge-aes-crypt
==========================

AES components from forge stripped of AMD support and fixed for browserify

# WARNING

This module rewrites parts of the sources from [forge](https://github.com/digitalbazaar/forge)
using [esprima](http://esprima.org/). Currently, only a subset is used, as this module is
aimed towards personal use.

This is an experimental approach with the intend of being able to bundle a subset of forge
inside a [browserifid](http://browserify.org/) application.

Currently the [random](./lib/random.js) seems to lack proper entropy generation under these
circumstances.

## building

Run the "import" script to transpile the forge source code into syncronous require modules:

    ./import.sh

An [script](./bin/import.js) build around esprima is used to rewrite sources from the main
library into syncronous modules that can be consumed by browserify.

The AMD boilerplate is stripped, and all interaction with the `forge` module is rewriten into
plain require statements, in addition to a number of small workarounds where working with the
AST proved harder then applying a small regex.

## publishing

Theoretically, the contents of this director could be published to npmjs.org as is, and then
installed using:

    npm install forge-aes-browserify

In your application, simply:

    var forge = require('forge-aes-browserify');

Exposes the subset of forge needed to encrypt and decrypt data using `AES` (see the [test](./test/index.js))
