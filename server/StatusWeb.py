# MIT License
# 
# Copyright (c) 2018 Mike Simms
# 
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
# 
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
# 
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

import argparse
import cherrypy
import mako
import os
import signal

ACCESS_LOG = 'access.log'
ERROR_LOG = 'error.log'

g_root_dir = os.path.dirname(os.path.abspath(__file__))
g_root_url = ''

def signal_handler(signal, frame):
    global g_app

    print "Exiting..."
    if g_app is not None:
        g_app.terminate()
    sys.exit(0)

class StatusWeb(object):
    def __init__(self):
        super(StatusWeb, self).__init__()

# Parse command line options.
parser = argparse.ArgumentParser()
parser.add_argument("--debug", action="store_true", default=False, help="Prevents the app from going into the background", required=False)
parser.add_argument("--port", type=int, default=8080, help="Port on which to listen", required=False)
parser.add_argument("--https", action="store_true", default=False, help="Runs the app as HTTPS", required=False)
parser.add_argument("--cert", default="cert.pem", help="Certificate file for HTTPS", required=False)
parser.add_argument("--privkey", default="privkey.pem", help="Private Key file for HTTPS", required=False)
parser.add_argument("--url", default="", help="URL of the server on which this is being run", required=False)

try:
    args = parser.parse_args()
except IOError as e:
    parser.error(e)
    sys.exit(1)

if args.debug:
    if args.https:
        g_root_url = "https://127.0.0.1:" + str(args.port)
    else:
        g_root_url = "http://127.0.0.1:" + str(args.port)
else:
    if args.https:
        g_root_url = 'https://' + args.url
    else:
        g_root_url = 'http://' + args.url

    Daemonizer(cherrypy.engine).subscribe()

if args.https:
    print "Running HTTPS...."
    cherrypy.server.ssl_module = 'builtin'
    cherrypy.server.ssl_certificate = args.cert
    print "Certificate File: " + args.cert
    cherrypy.server.ssl_private_key = args.privkey
    print "Private Key File: " + args.privkey

signal.signal(signal.SIGINT, signal_handler)
mako.collection_size = 100
mako.directories = "templates"

g_app = StatusWeb()

conf = {
    '/':
    {
        'tools.staticdir.root': g_root_dir,
        'tools.my_auth.on': True,
        'tools.sessions.on': True,
        'tools.sessions.name': 'my_auth'
    },
    '/css':
    {
        'tools.staticdir.on': True,
        'tools.staticdir.dir': 'css'
    },
    '/images':
    {
        'tools.staticdir.on': True,
        'tools.staticdir.dir': 'images',
    },
    '/media':
    {
        'tools.staticdir.on': True,
        'tools.staticdir.dir': 'media',
    },
    '/.well-known':
    {
        'tools.staticdir.on': True,
        'tools.staticdir.dir': '.well-known',
    },
}

cherrypy.config.update({
    'server.socket_host': '127.0.0.1',
    'server.socket_port': args.port,
    'requests.show_tracebacks': False,
    'log.access_file': ACCESS_LOG,
    'log.error_file': ERROR_LOG})

cherrypy.quickstart(g_app, config=conf)
