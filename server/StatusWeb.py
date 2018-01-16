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
import datetime
import logging
import mako
import os
import signal
import sys
import StatusApi
import StatusDb

from cherrypy import tools
from cherrypy.process.plugins import Daemonizer
from mako.lookup import TemplateLookup
from mako.template import Template

ACCESS_LOG = 'access.log'
ERROR_LOG = 'error.log'

g_root_dir = os.path.dirname(os.path.abspath(__file__))
g_root_url = ''
g_tempmod_dir = os.path.join(g_root_dir, 'tempmod')

def signal_handler(signal, frame):
    global g_app

    print "Exiting..."
    if g_app is not None:
        g_app.terminate()
    sys.exit(0)

class StatusWeb(object):
    def __init__(self):
        super(StatusWeb, self).__init__()
        self.database = StatusDb.MongoDatabase(g_root_dir)

    def terminate(self):
        print "Terminating"

    # Helper function for building the navigation bar.
    @staticmethod
    def create_navbar():
        navbar_str = "<nav>\n" \
            "\t<ul>\n" \
            "\t</ul>\n" \
            "</nav>"
        return navbar_str

    # Renders the error page.
    @cherrypy.expose
    def error(self, error_str=None):
        try:
            cherrypy.response.status = 500
            my_template = Template(filename=g_error_html_file, module_directory=g_tempmod_dir)
            if error_str is None:
                error_str = "Internal Error."
        except:
            pass
        return my_template.render(root_url=g_root_url, error=error_str)

    # Page for displaying graphs about a particular device.
    @cherrypy.expose
    def device(self, device_id, *args, **kw):
        try:
            cpu_str = ""
            ram_str = ""
            gpu_str = ""

            statuses = self.database.retrieve_status(device_id)
            if statuses is not None:
                for status in statuses:
                    if "datetime" in status:
                        datetime_str = str(status["datetime"])
                        if "cpu - percent" in status:
                            cpu_percent = status["cpu - percent"]
                            cpu_str += "\t\t\t\t{ date: new Date(" + datetime_str + "), value: " + str(cpu_percent) + " },\n"
                        if "virtual memory - percent" in status:
                            ram_percent = status["virtual memory - percent"]
                            ram_str += "\t\t\t\t{ date: new Date(" + datetime_str + "), value: " + str(ram_percent) + " },\n"
                        if "gpu - percent" in status:
                            gpu_percent = status["gpu - percent"]
                            gpu_str += "\t\t\t\t{ date: new Date(" + datetime_str + "), value: " + str(gpu_percent) + " },\n"

            device_html_file = os.path.join(g_root_dir, 'html', 'device.html')
            my_template = Template(filename=device_html_file, module_directory=g_tempmod_dir)
            return my_template.render(nav=self.create_navbar(), root_url=g_root_url, device_id=device_id, cpu=cpu_str, memory=ram_str, gpu=gpu_str)
        except:
            cherrypy.log.error('Unhandled exception in device', 'EXEC', logging.WARNING)
        return ""

    # Renders the login page.
    @cherrypy.expose
    def login(self):
        try:
            login_html_file = os.path.join(g_root_dir, 'html', 'login.html')
            my_template = Template(filename=login_html_file, module_directory=g_tempmod_dir)
            result = my_template.render(root_url=g_root_url)
        except:
            result = self.error()
        return result

    # Renders the create login page.
    @cherrypy.expose
    def create_login(self):
        try:
            create_login_html_file = os.path.join(g_root_dir, 'html', 'create_login.html')
            my_template = Template(filename=create_login_html_file, module_directory=g_tempmod_dir)
            result = my_template.render(root_url=g_root_url)
        except:
            result = self.error()
        return result

    # Renders the index (default) page.
    @cherrypy.expose
    def index(self):
        return self.login()

    # Endpoint for API calls.
    @cherrypy.expose
    def api(self, *args, **kw):
        if len(args) > 0:
            api_version = args[0]
            if api_version == '1.0':
                api = StatusApi.StatusApi(g_root_dir)
                handled = api.handle_api_1_0_request(args[1:], kw)
                if not handled:
                    cherrypy.response.status = 400
            else:
                cherrypy.response.status = 400
        else:
            cherrypy.response.status = 400

# Parse command line options.
parser = argparse.ArgumentParser()
parser.add_argument("--debug", action="store_true", default=False, help="Prevents the app from going into the background", required=False)
parser.add_argument("--port", type=int, default=8282, help="Port on which to listen", required=False)
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
        'tools.staticdir.root': g_root_dir
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
