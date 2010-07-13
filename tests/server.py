#!/usr/bin/env python
#
# SSL server for Forge tests.
#
# - The server changes to the directory of the server script.
# - SSL uses "server.key" and "server.crt".
# - Sever performs basic static file serving.
# - Defaults to SSL on port 19400.
#
#   $ ./server.py [-p PORT] [--ssl]
#
# If you just need a simple HTTP server, also consider:
#   $ python -m SimpleHTTPServer 19400
#

import SimpleHTTPServer
import SocketServer
from optparse import OptionParser
import os
try:
    import ssl
    have_ssl = True
except ImportError:
    have_ssl = False

def main():
    usage = "Usage: %prog [options]"
    parser = OptionParser(usage=usage)
    parser.add_option("-p", "--port", dest="port", type="int",
            help="serve on PORT", metavar="PORT", default=19400)
    parser.add_option("", "--tls", dest="tls", action="store_true",
            help="serve HTTPS", default=False)
    (options, args) = parser.parse_args()

    # Change to script dir so SSL and test files are in current dir.
    script_dir = os.path.dirname(os.path.realpath(__file__))
    os.chdir(script_dir)

    Handler = SimpleHTTPServer.SimpleHTTPRequestHandler
    httpd = SocketServer.TCPServer(("", options.port), Handler)
    if options.tls:
        if not have_ssl:
            raise Exception("SSL support from Python 2.6 or later is required.")
        httpd.socket = ssl.wrap_socket(
            httpd.socket,
            keyfile="server.key",
            certfile="server.crt",
            server_side=True)

    print "Forge Test Server. Use ctrl-C to exit."
    print "Serving from \"%s\"." % (script_dir)
    print "%s://%s:%d/" % \
            (("https" if options.tls else "http"),
            httpd.server_address[0],
            options.port)
    httpd.serve_forever()

if __name__ == "__main__":
    main()

