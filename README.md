Forge
=====

A native implementation of [TLS][] in [JavaScript][] and tools to write network
based web apps.

Introduction
------------

The Forge software is a fully native implementation of the [TLS][] protocol in
JavaScript as well as a set of tools for developing Web Apps that utilize many
network resources.

Features
--------

### forge.debug

Provides storage of debugging information normally inaccessible in
closures for viewing/investigation.

### forge.util

Provides utility functions, including byte buffer support, base64,
bytes to/from hex, zlib inflate/deflate, etc.

### forge.log

Provides logging to a javascript console using various categories and
levels of verbosity.

### forge.task

Provides queuing and synchronizing tasks in a web application.

### forge.aes

Provides basic [AES][] encryption and decryption in CBC mode.

### forge.md.md5

Provides [MD5][] message digests.

### forge.md.sha1

Provides [SHA-1][] message digests.

### forge.md.sha256

Provides [SHA-256][] message digests.

### forge.hmac

Provides [HMAC][] w/any supported message digest algorithm.

### forge.pkcs5.pbkdf2

Provides the password-based key-derivation function from [PKCS#5][].

### forge.pkcs7

Provides cryptographically protected messages from [PKCS#7][].

### forge.pkcs12

Provides the cryptographic archive file format from [PKCS#12][].

### forge.prng

Provides a [Fortuna][]-based cryptographically-secure pseudo-random number
generator, to be used with a cryptographic function backend, ie: [AES][].

### forge.random

Provides an interface to getting cryptographically-secure bytes using
[AES][] as a backend for forge.prng.

### forge.asn

Provides [ASN.1][] DER encoding and decoding.

### forge.pki

Provides [X.509][] certificate and RSA public and private key encoding,
decoding, encryption/decryption, and signing/verifying.

### forge.tls

Provides a native javascript client and server-side [TLS][] implementation.

### forge.socket

Provides an interface to create and use raw sockets provided via Flash.

### forge.http

Provides a native [JavaScript][] mini-implementation of an http client that
uses pooled sockets.

### forge.xhr

Provides an XmlHttpRequest implementation using forge.http as a backend.

### mod\_fsp

Provides an [Apache][] module that can serve up a Flash Socket Policy. See
`mod_fsp/README` for more details. This module makes it easy to modify
an [Apache][] server to allow cross domain requests to be made to it.


Getting Started
---------------

Requirements

* General
  * GNU autotools for the build infrastructure.
* Flash
  * Optional: A pre-built SocketPool.swf is included.
  * Adobe Flex 3 SDK to build the Flash socket code.
  * http://opensource.adobe.com/wiki/display/flexsdk/
* Testing
  * Optional: Only needed for fast session cache during testing.
  * Python and OpenSSL development environment to build a special SSL module
    with session cache support.
  * http://www.python.org/dev/
  * http://www.openssl.org/
  * Debian users should install python-dev and libssl-dev.

### Building ###

To build the whole project, run the following::

    $ ./build-setup
    $ make

This will create the SWF, symlink all the JavaScript files, and build a Python
SSL module for testing. To see configure options, run `./configure --help`.

### Testing ###

A test server is provided which can be run in TLS mode and non-TLS mode. Use
the --help option to get help for configuring ports. The server will print out
the local URL you can vist to run tests.

Some of the simplier tests should be run with just the non-TLS server::

    $ ./tests/server.py

More advanced tests need TLS enabled::

    $ ./tests/server.py --tls


Library Details
---------------

* http://digitalbazaar.com/2010/07/20/javascript-tls-1/
* http://digitalbazaar.com/2010/07/20/javascript-tls-2/

Contact
-------

* Code: https://github.com/digitalbazaar/forge
* Bugs: https://github.com/digitalbazaar/forge/issues
* Email: support@digitalbazaar.com

[AES]: http://en.wikipedia.org/wiki/Advanced_Encryption_Standard
[ASN.1]: http://en.wikipedia.org/wiki/ASN.1
[Apache]: http://httpd.apache.org/
[Fortuna]: http://en.wikipedia.org/wiki/Fortuna_(PRNG)
[HMAC]: http://en.wikipedia.org/wiki/HMAC
[JavaScript]: http://en.wikipedia.org/wiki/JavaScript
[MD5]: http://en.wikipedia.org/wiki/MD5
[PKCS#5]: http://en.wikipedia.org/wiki/PKCS
[PKCS#7]: http://en.wikipedia.org/wiki/Cryptographic_Message_Syntax
[PKCS#12]: http://en.wikipedia.org/wiki/PKCS_%E2%99%AF12
[SHA-1]: http://en.wikipedia.org/wiki/SHA-1
[SHA-256]: http://en.wikipedia.org/wiki/SHA-256
[TLS]: http://en.wikipedia.org/wiki/Transport_Layer_Security
[X.509]: http://en.wikipedia.org/wiki/SHA-256
