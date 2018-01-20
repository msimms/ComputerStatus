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
import bcrypt
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
SESSION_KEY = '_computerstatus_username'
MIN_PASSWORD_LEN = 8

g_root_dir = os.path.dirname(os.path.abspath(__file__))
g_root_url = ''
g_tempmod_dir = os.path.join(g_root_dir, 'tempmod')
g_app = None

def signal_handler(signal, frame):
    global g_app

    print "Exiting..."
    if g_app is not None:
        g_app.terminate()
    sys.exit(0)

def check_auth(*args, **kwargs):
    # A tool that looks in config for 'auth.require'. If found and it is not None, a login
    # is required and the entry is evaluated as a list of conditions that the user must fulfill
    conditions = cherrypy.request.config.get('auth.require', None)
    if conditions is not None:
        requested_url = cherrypy.request.request_line.split()[1]
        requested_url_parts = requested_url.split('/')
        requested_url_parts = filter(lambda part: part != '', requested_url_parts)

        # If the user is trying to view an activity then make sure they have permissions
        # to view it. First check to see if it's a public activity.
        if requested_url_parts[0] == "device":
            pass

        username = cherrypy.session.get(SESSION_KEY)
        if username:
            cherrypy.request.login = username
            for condition in conditions:
                # A condition is just a callable that returns true or false
                if not condition():
                    raise cherrypy.HTTPRedirect("/login")
        else:
            raise cherrypy.HTTPRedirect("/login")

def require(*conditions):
    # A decorator that appends conditions to the auth.require config variable.
    def decorate(f):
        if not hasattr(f, '_cp_config'):
            f._cp_config = dict()
        if 'auth.require' not in f._cp_config:
            f._cp_config['auth.require'] = []
        f._cp_config['auth.require'].extend(conditions)
        return f
    return decorate

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
            "\t\t<li><a href=\"" + g_root_url + "/dashboard/\">Dashboard</a></li>\n" \
            "\t</ul>\n" \
            "</nav>"
        return navbar_str

    # Renders the error page.
    @cherrypy.expose
    def error(self, error_str=None):
        try:
            cherrypy.response.status = 500
            error_html_file = os.path.join(g_root_dir, 'html', 'error.html')
            my_template = Template(filename=error_html_file, module_directory=g_tempmod_dir)
            if error_str is None:
                error_str = "Internal Error."
        except:
            pass
        return my_template.render(root_url=g_root_url, error=error_str)

    def format_graph_point(self, datetime_str, value):
        graph_str = "\t\t\t\t{ date: new Date(" + datetime_str + "), value: " + str(value) + " },\n"
        return graph_str

    # Page for displaying graphs about a particular device.
    @cherrypy.expose
    def device(self, device_id, *args, **kw):
        try:
            cpu_str = ""
            ram_str = ""
            gpu_str = ""
            gpu_temp_str = ""

            last_cpu_value = ""
            last_ram_value = ""
            last_gpu_value = ""
            last_gpu_temp_value = ""

            statuses = self.database.retrieve_status(device_id)
            if statuses is not None:
                for status in statuses:
                    if "datetime" in status:
                        datetime_num = int(status["datetime"]) * 1000
                        datetime_str = str(datetime_num)
                        if "cpu - percent" in status:
                            last_cpu_value = status["cpu - percent"]
                            cpu_str += self.format_graph_point(datetime_str, last_cpu_value)
                        else:
                            cpu_str += self.format_graph_point(datetime_str, 0)
                        if "virtual memory - percent" in status:
                            last_ram_value = status["virtual memory - percent"]
                            ram_str += self.format_graph_point(datetime_str, last_ram_value)
                        else:
                            ram_str += self.format_graph_point(datetime_str, 0)
                        if "gpu - percent" in status:
                            last_gpu_value = status["gpu - percent"]
                            gpu_str += self.format_graph_point(datetime_str, last_gpu_value)
                        else:
                            gpu_str += self.format_graph_point(datetime_str, 0)
                        if "gpu - temperature" in status:
                            last_gpu_temp_value = status["gpu - temperature"]
                            gpu_temp_str += self.format_graph_point(datetime_str, last_gpu_temp_value)
                        else:
                            gpu_temp_str += self.format_graph_point(datetime_str, 0)

            table_str  = "\t<table>\n"
            if len(last_cpu_value) > 0:
                table_str += "\t\t<td>Current CPU Utilization</td><td>" + str(last_cpu_value) + "%</td><tr>\n"
            else:
                cpu_str = ""
            if len(last_ram_value) > 0:
                table_str += "\t\t<td>Current RAM Utilization</td><td>" + str(last_ram_value) + "%</td><tr>\n"
            else:
                ram_str = ""
            if len(last_gpu_value) > 0:
                table_str += "\t\t<td>Current GPU Utilization</td><td>" + str(last_gpu_value) + "%</td><tr>\n"
            else:
                gpu_str = ""
            if len(last_gpu_temp_value) > 0:
                table_str += "\t\t<td>Current GPU Temperature</td><td>" + str(last_gpu_temp_value) + "</td><tr>\n"
            else:
                gpu_temp_str = ""
            table_str += "\t</table>\n"

            device_html_file = os.path.join(g_root_dir, 'html', 'device.html')
            my_template = Template(filename=device_html_file, module_directory=g_tempmod_dir)
            return my_template.render(nav=self.create_navbar(), root_url=g_root_url, device_id=device_id, graph1=cpu_str, graph2=ram_str, graph3=gpu_str, graph4=gpu_temp_str, table=table_str)
        except:
            cherrypy.log.error('Unhandled exception in device', 'EXEC', logging.WARNING)
        return ""

    @cherrypy.expose
    def claim_device(self, device_id):
        try:
            # Get the logged in user.
            username = cherrypy.session.get(SESSION_KEY)
            if username is None:
                raise cherrypy.HTTPRedirect("/login")

            # Get the details of the logged in user.
            user_id, user_hash, user_realname = self.database.retrieve_user(username)

            # Add the device id to the database.
            self.database.claim_device(user_id, device_id)

            # Refresh the dashboard page.
            raise cherrypy.HTTPRedirect("/dashboard")
        except cherrypy.HTTPRedirect as e:
            raise e
        except:
            cherrypy.log.error('Unhandled exception in dashboard', 'EXEC', logging.WARNING)
        return ""

    # Page for displaying the devices owned by a particular user.
    @cherrypy.expose
    @require()
    def dashboard(self, *args, **kw):
        try:
            # Get the logged in user.
            username = cherrypy.session.get(SESSION_KEY)
            if username is None:
                raise cherrypy.HTTPRedirect("/login")

            # Get the details of the logged in user.
            user_id, user_hash, user_realname = self.database.retrieve_user(username)

            # Get the user's devices.
            devices = self.database.retrieve_user_devices(user_id)

            # Render a table containing the user's devices.
            device_table_str  = "\t<table>\n"
            if devices is not None:
                for device in devices:
                    device_table_str += "\t\t<td><a href=\"" + g_root_url + "/device/" + str(device) + "\">" + str(device) + "</a></td><tr>\n"
            device_table_str += "\t<table>\n"

            # Render the dashboard page.
            dashboard_html_file = os.path.join(g_root_dir, 'html', 'dashboard.html')
            my_template = Template(filename=dashboard_html_file, module_directory=g_tempmod_dir)
            return my_template.render(nav=self.create_navbar(), root_url=g_root_url, devices=device_table_str)
        except cherrypy.HTTPRedirect as e:
            raise e
        except:
            cherrypy.log.error('Unhandled exception in dashboard', 'EXEC', logging.WARNING)
        return ""

    def authenticate_user(self, email, password):
        if self.database is None:
            return False, "No database."
        if len(email) == 0:
            return False, "An email address was not provided."
        if len(password) < MIN_PASSWORD_LEN:
            return False, "The password is too short."

        user_id, db_hash1, user_name = self.database.retrieve_user(email)
        if db_hash1 is None:
            return False, "The user could not be found."
        db_hash2 = bcrypt.hashpw(password.encode('utf-8'), db_hash1.encode('utf-8'))
        if db_hash1 == db_hash2:
            return True, "The user has been logged in."
        return False, "The password is invalid."

    def create_user(self, email, realname, password1, password2):
        if self.database is None:
            return False, "No database."
        if len(email) == 0:
            return False, "Email address not provided."
        if len(realname) == 0:
            return False, "Name not provided."
        if len(password1) < MIN_PASSWORD_LEN:
            return False, "The password is too short."
        if password1 != password2:
            return False, "The passwords do not match."
        if self.database.retrieve_user(email) is None:
            return False, "The user already exists."

        salt = bcrypt.gensalt()
        hash = bcrypt.hashpw(password1.encode('utf-8'), salt)
        if not self.database.create_user(email, realname, hash):
            return False, "An internal error was encountered when creating the user."

        return True, "The user was created."

    # Processes a login.
    @cherrypy.expose
    def submit_login(self, *args, **kw):
        try:
            email = cherrypy.request.params.get("email")
            password = cherrypy.request.params.get("password")

            if email is None or password is None:
                return self.error("An email address and password were not provided.")
            else:
                user_logged_in, info_str = self.authenticate_user(email, password)
                if user_logged_in:
                    cherrypy.session.regenerate()
                    cherrypy.session[SESSION_KEY] = cherrypy.request.login = email
                    result = self.dashboard(email, None, None)
                else:
                    error_msg = "Unable to authenticate the user."
                    if len(info_str) > 0:
                        error_msg += " "
                        error_msg += info_str
                    result = self.error(error_msg)
            return result
        except:
            cherrypy.log.error('Unhandled exception in submit_login', 'EXEC', logging.WARNING)
        return self.error()

    # Creates a new login.
    @cherrypy.expose
    def submit_new_login(self, email, realname, password1, password2, *args, **kw):
        try:
            user_created, info_str = self.create_user(email, realname, password1, password2)
            if user_created:
                cherrypy.session.regenerate()
                cherrypy.session[SESSION_KEY] = cherrypy.request.login = email
                result = self.dashboard(email, *args, **kw)
            else:
                error_msg = "Unable to create the user."
                if len(info_str) > 0:
                    error_msg += " "
                    error_msg += info_str
                result = self.error(error_msg)
            return result
        except:
            cherrypy.log.error('Unhandled exception in submit_new_login', 'EXEC', logging.WARNING)
        return self.error()

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
parser.add_argument("--url", default="homecomputerstatus.com", help="URL of the server on which this is being run", required=False)

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

cherrypy.tools.statusweb_auth = cherrypy.Tool('before_handler', check_auth)

conf = {
    '/':
    {
        'tools.staticdir.root': g_root_dir,
        'tools.statusweb_auth.on': True,
        'tools.sessions.on': True,
        'tools.sessions.name': 'statusweb_auth'
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
