# -*- coding: utf-8 -*-
# 
# # MIT License
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
"""Main application, contains all web page handlers"""

import argparse
import inspect
import json
import logging
import os
import signal
import sys
import cherrypy
import mako
import markdown
import Api
import InputChecker
import StatusDb
import UserMgr

currentdir = os.path.dirname(os.path.abspath(inspect.getfile(inspect.currentframe())))
parentdir = os.path.dirname(currentdir)
clientdir = os.path.join(parentdir, 'client')
sys.path.insert(0, clientdir)
import keys

from cherrypy.process.plugins import Daemonizer
from mako.lookup import TemplateLookup
from mako.template import Template

ACCESS_LOG = 'access.log'
ERROR_LOG = 'error.log'

LOGIN_URL = '/login'
DASHBOARD_URL = '/dashboard'
HTML_DIR = 'html'

g_root_dir = os.path.dirname(os.path.abspath(__file__))
g_root_url = ''
g_tempmod_dir = os.path.join(g_root_dir, 'tempmod')
g_app = None

def signal_handler(signal, frame):
    global g_app

    logging.info("Exiting...")
    if g_app is not None:
        g_app.terminate()
    sys.exit(0)

@cherrypy.tools.register('before_finalize', priority=60)
def secureheaders():
    headers = cherrypy.response.headers
    headers['X-Frame-Options'] = 'DENY'
    headers['X-XSS-Protection'] = '1; mode=block'
    headers['Content-Security-Policy'] = "default-src='self'"

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

        username = g_app.user_mgr.get_logged_in_user()
        if username:
            cherrypy.request.login = username
            for condition in conditions:
                # A condition is just a callable that returns true or false
                if not condition():
                    raise cherrypy.HTTPRedirect(LOGIN_URL)
        else:
            raise cherrypy.HTTPRedirect(LOGIN_URL)

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
    """Class containing the URL handlers."""

    def __init__(self, user_mgr):
        super(StatusWeb, self).__init__()
        self.user_mgr = user_mgr
        self.database = StatusDb.MongoDatabase(g_root_dir)

    def terminate(self):
        """Destructor"""
        logging.info("Terminating...")
        self.user_mgr.terminate()
        self.user_mgr = None

    def log_error(self, log_str):
        """Writes an error message to the log file."""
        logger = logging.getLogger()
        logger.error(log_str)

    @staticmethod
    def create_navbar(logged_in=True):
        """Helper function for building the navigation bar."""
        navbar_str = "<nav>\n\t<ul>\n"
        navbar_str += "\t\t<li><a href=\"https://github.com/msimms/ComputerStatus/\">GitHub</a></li>\n"
        if logged_in is True:
            navbar_str += "\t\t<li><a href=\"" + g_root_url + "/dashboard/\">Dashboard</a></li>\n"
            navbar_str += "\t\t<li><a href=\"" + g_root_url + "/settings/\">Settings</a></li>\n"
            navbar_str += "\t\t<li><a href=\"" + g_root_url + "/logout/\">Log Out</a></li>\n"
        navbar_str += "\t</ul>\n</nav>"
        return navbar_str

    @cherrypy.expose
    def error(self, error_str=None):
        """Renders the error page."""
        try:
            cherrypy.response.status = 500
            error_html_file = os.path.join(g_root_dir, HTML_DIR, 'error.html')
            my_template = Template(filename=error_html_file, module_directory=g_tempmod_dir)
            if error_str is None:
                error_str = "Internal Error."
        except:
            self.log_error("Unhandled exception in " + StatusWeb.error.__name__)
        return my_template.render(root_url=g_root_url, error=error_str)

    @cherrypy.expose
    def device(self, device_id, *args, **kw):
        """Page for displaying graphs about a particular device."""
        try:
            title_str = self.database.retrieve_device_name(device_id)
            if title_str is None:
                title_str = "Device ID: " + str(device_id)

            table_str = "\t<table>\n"
            degree_sign = u'\N{DEGREE SIGN}'

            statuses = self.database.retrieve_status(device_id, 1)
            if statuses is not None and len(statuses) > 0:
                last_status = statuses[len(statuses) - 1]

                if keys.KEY_CPU_PERCENT in last_status:
                    table_str += "\t\t<td>Current CPU Utilization</td><td>" + str(last_status[keys.KEY_CPU_PERCENT]) + "%</td><tr>\n"
                if keys.KEY_CPU_TEMPERATURE in last_status:
                    table_str += "\t\t<td>Current CPU Temperature</td><td>" + str(last_status[keys.KEY_CPU_TEMPERATURE]) + degree_sign + "C</td><tr>\n"
                if keys.KEY_VIRTUAL_MEM_PERCENT in last_status:
                    table_str += "\t\t<td>Current RAM Utilization</td><td>" + str(last_status[keys.KEY_VIRTUAL_MEM_PERCENT]) + "%</td><tr>\n"
                if keys.KEY_GPU_PERCENT in last_status:
                    table_str += "\t\t<td>Current GPU Utilization</td><td>" + str(last_status[keys.KEY_GPU_PERCENT]) + "%</td><tr>\n"
                if keys.KEY_GPU_TEMPERATURE in last_status:
                    table_str += "\t\t<td>Current GPU Temperature</td><td>" + str(last_status[keys.KEY_GPU_TEMPERATURE]) + degree_sign + "C</td><tr>\n"
                if keys.KEY_NETWORK_BYTES_SENT in last_status:
                    table_str += "\t\t<td>Bytes Sent</td><td>" + str(last_status[keys.KEY_NETWORK_BYTES_SENT]) + " Bytes </td><tr>\n"
                if keys.KEY_NETWORK_BYTES_RECEIVED in last_status:
                    table_str += "\t\t<td>Bytes Received</td><td>" + str(last_status[keys.KEY_NETWORK_BYTES_RECEIVED]) + " Bytes </td><tr>\n"

            table_str += "\t</table>\n"

            device_html_file = os.path.join(g_root_dir, HTML_DIR, 'device.html')
            my_template = Template(filename=device_html_file, module_directory=g_tempmod_dir)
            return my_template.render(nav=self.create_navbar(), root_url=g_root_url, title=title_str, device_id=device_id, table=table_str)
        except:
            self.log_error('Unhandled exception in ' + StatusWeb.device.__name__)
        return ""

    @cherrypy.expose
    def claim_device(self, device_id):
        """Associates a device with a user."""
        try:
            # Get the logged in user.
            username = self.user_mgr.get_logged_in_user()
            if username is None:
                raise cherrypy.HTTPRedirect(LOGIN_URL)

            # Get the details of the logged in user.
            user_id, _, _ = self.user_mgr.retrieve_user(username)
            if user_id is None:
                self.log_error('Unknown user ID')
                raise cherrypy.HTTPRedirect(LOGIN_URL)

            # Make sure the device ID is real.
            device_status = self.database.retrieve_status(device_id, 1)
            if device_status is None or len(device_status) == 0:
                self.log_error('Unknown device ID')
                raise cherrypy.HTTPRedirect(DASHBOARD_URL)

            # Add the device id to the database.
            self.database.claim_device(user_id, device_id)

            # Refresh the dashboard page.
            raise cherrypy.HTTPRedirect(DASHBOARD_URL)
        except cherrypy.HTTPRedirect as e:
            raise e
        except:
            self.log_error('Unhandled exception in ' + StatusWeb.claim_device.__name__)
        return ""

    @cherrypy.expose
    def delete_device(self, *args, **kw):
        """Deletes the device with the specified ID, assuming it is owned by the current user."""
        try:
            # Get the logged in user.
            username = self.user_mgr.get_logged_in_user()
            if username is None:
                raise cherrypy.HTTPRedirect(LOGIN_URL)

            # Get the details of the logged in user.
            user_id, _, _ = self.user_mgr.retrieve_user(username)
            if user_id is None:
                self.log_error('Unknown user ID')
                raise cherrypy.HTTPRedirect(LOGIN_URL)

            # Get the device ID from the push request.
            device_id = cherrypy.request.params.get("device_id")

            # Get the user's devices.
            devices = self.database.retrieve_user_devices(user_id)
            if not device_id in devices:
                self.log_error('Unknown device ID')
                raise cherrypy.HTTPRedirect(DASHBOARD_URL)

            # Delete the device.
            self.database.delete_status(device_id)
            self.database.delete_device_attributes(device_id)
            self.database.unclaim_device(user_id, device_id)

            # Refresh the dashboard page.
            raise cherrypy.HTTPRedirect(DASHBOARD_URL)
        except cherrypy.HTTPRedirect as e:
            raise e
        except:
            self.log_error('Unhandled exception in ' + StatusWeb.delete_device.__name__)
        return ""

    @cherrypy.expose
    def set_device_name(self, device_id, name):
        """Associates a name with a device's unique identifier."""
        try:
            # Get the logged in user.
            username = self.user_mgr.get_logged_in_user()
            if username is None:
                raise cherrypy.HTTPRedirect(LOGIN_URL)

            # Get the details of the logged in user.
            user_id, _, _ = self.user_mgr.retrieve_user(username)
            if user_id is None:
                self.log_error('Unknown user ID')
                raise cherrypy.HTTPRedirect(LOGIN_URL)

            # Validate the device name.
            if not InputChecker.is_valid(name):
                self.log_error('Invalid device name')
                raise cherrypy.HTTPRedirect(DASHBOARD_URL)

            # Get the user's devices.
            devices = self.database.retrieve_user_devices(user_id)
            if not device_id in devices:
                self.log_error('Unknown device ID')
                raise cherrypy.HTTPRedirect(DASHBOARD_URL)

            # Add the device id to the database.
            self.database.create_device_name(device_id, name)

            # Refresh the dashboard page.
            raise cherrypy.HTTPRedirect(DASHBOARD_URL)
        except cherrypy.HTTPRedirect as e:
            raise e
        except:
            self.log_error('Unhandled exception in ' + StatusWeb.set_device_name.__name__)
        return ""

    @cherrypy.expose
    def set_device_attribute_color(self, device_id, attribute, color):
        """Associates a color with a device."""
        try:
            # Get the logged in user.
            username = self.user_mgr.get_logged_in_user()
            if username is None:
                raise cherrypy.HTTPRedirect(LOGIN_URL)

            # Get the details of the logged in user.
            user_id, _, _ = self.user_mgr.retrieve_user(username)
            if user_id is None:
                self.log_error('Unknown user ID')
                raise cherrypy.HTTPRedirect(LOGIN_URL)

            # Get the user's devices.
            devices = self.database.retrieve_user_devices(user_id)
            if not device_id in devices:
                self.log_error('Unknown device ID')
                raise cherrypy.HTTPRedirect(DASHBOARD_URL)

            # Add the device id to the database.
            self.database.create_device_attribute_color(device_id, attribute, color)

            # Refresh the dashboard page.
            raise cherrypy.HTTPRedirect(DASHBOARD_URL)
        except cherrypy.HTTPRedirect as e:
            raise e
        except:
            self.log_error('Unhandled exception in ' + StatusWeb.set_device_attribute_color.__name__)
        return ""

    @cherrypy.expose
    @require()
    def dashboard(self, *args, **kw):
        """Page for displaying the devices owned by a particular user."""
        try:
            # Get the logged in user.
            username = self.user_mgr.get_logged_in_user()
            if username is None:
                raise cherrypy.HTTPRedirect(LOGIN_URL)

            # Get the details of the logged in user.
            user_id, _, _ = self.user_mgr.retrieve_user(username)
            if user_id is None:
                self.log_error('Unknown user ID')
                raise cherrypy.HTTPRedirect(LOGIN_URL)

            # Get the user's devices.
            devices = self.database.retrieve_user_devices(user_id)

            # Render a table containing the user's devices.
            device_table_str = "\t<table>\n"
            device_table_str += "\t\t<td><b>Name</b></td><td><b>Device ID</b></td><td></td><tr>\n"
            if devices is not None:
                for device in devices:
                    device_id_str = str(device)
                    device_name = self.database.retrieve_device_name(device_id_str)
                    if device_name is None:
                        device_name = "Untitled"
                    device_table_str += "\t\t<td>" + device_name + "</td><td><a href=\"" + g_root_url + "/device/" + device_id_str + "\">" + device_id_str + "</a></td><td><button type=\"button\" onclick=\"return on_delete('" + device_id_str + "')\">Delete</button></td><tr>\n"
            device_table_str += "\t</table>\n"

            # Render the dashboard page.
            dashboard_html_file = os.path.join(g_root_dir, HTML_DIR, 'dashboard.html')
            my_template = Template(filename=dashboard_html_file, module_directory=g_tempmod_dir)
            return my_template.render(nav=self.create_navbar(), root_url=g_root_url, devices=device_table_str)
        except cherrypy.HTTPRedirect as e:
            raise e
        except:
            self.log_error('Unhandled exception in ' + StatusWeb.dashboard.__name__)
        return ""

    @cherrypy.expose
    @require()
    def settings(self, *args, **kw):
        """Renders the user's settings page."""
        try:
            # Get the logged in user.
            username = self.user_mgr.get_logged_in_user()
            if username is None:
                raise cherrypy.HTTPRedirect(LOGIN_URL)

            # Get the details of the logged in user.
            user_id, _, user_realname = self.user_mgr.retrieve_user(username)
            if user_id is None:
                self.log_error('Unknown user ID')
                raise cherrypy.HTTPRedirect(LOGIN_URL)

            # Render from template.
            html_file = os.path.join(g_root_dir, HTML_DIR, 'settings.html')
            my_template = Template(filename=html_file, module_directory=g_tempmod_dir)
            return my_template.render(nav=self.create_navbar(), root_url=g_root_url, email=username, name=user_realname)
        except cherrypy.HTTPRedirect as e:
            raise e
        except:
            self.log_error('Unhandled exception in ' + StatusWeb.settings.__name__)
        return self.error()

    @cherrypy.expose
    def submit_login(self, *args, **kw):
        """Processes a login."""
        try:
            email = cherrypy.request.params.get("email")
            password = cherrypy.request.params.get("password")

            if email is None or password is None:
                raise Exception("An email address and password were not provided.")
            else:
                if self.user_mgr.authenticate_user(email, password):
                    self.user_mgr.create_new_session(email)
                    raise cherrypy.HTTPRedirect(DASHBOARD_URL)
                else:
                    raise Exception("Unknown error.")
        except cherrypy.HTTPRedirect as e:
            raise e
        except Exception as e:
            error_msg = 'Unable to authenticate the user. ' + str(e.args[0])
            self.log_error(error_msg)
            return self.error(error_msg)
        except:
            self.log_error('Unhandled exception in ' + StatusWeb.submit_login.__name__)
        return self.error()

    @cherrypy.expose
    def submit_new_login(self, email, realname, password1, password2, *args, **kw):
        """Creates a new login."""
        try:
            if self.user_mgr.create_user(email, realname, password1, password2):
                self.user_mgr.create_new_session(email)
                raise cherrypy.HTTPRedirect(DASHBOARD_URL)
            else:
                raise Exception("Unknown error.")
        except cherrypy.HTTPRedirect as e:
            raise e
        except Exception as e:
            error_msg = 'Unable to create the user. ' + str(e.args[0])
            self.log_error(error_msg)
            return self.error(error_msg)
        except:
            self.log_error('Unhandled exception in ' + StatusWeb.submit_new_login.__name__)
        return self.error()

    @cherrypy.expose
    def login(self):
        """Renders the login page."""
        try:
            # If a user is already logged in then go straight to the landing page.
            username = self.user_mgr.get_logged_in_user()
            if username is not None:
                raise cherrypy.HTTPRedirect(DASHBOARD_URL)

            html = ""
            readme_file_name = os.path.realpath(os.path.join(g_root_dir, '..', 'README.md'))
            with open(readme_file_name, 'r') as readme_file:
                md = readme_file.read()
                extensions = ['extra', 'smarty']
                html = markdown.markdown(md, extensions=extensions, output_format='html5')

            login_html_file = os.path.join(g_root_dir, HTML_DIR, 'login.html')
            my_template = Template(filename=login_html_file, module_directory=g_tempmod_dir)
            result = my_template.render(nav=self.create_navbar(False), root_url=g_root_url, readme=html)
        except cherrypy.HTTPRedirect as e:
            raise e
        except:
            result = self.error()
        return result

    @cherrypy.expose
    def create_login(self):
        """Renders the create login page."""
        try:
            create_login_html_file = os.path.join(g_root_dir, HTML_DIR, 'create_login.html')
            my_template = Template(filename=create_login_html_file, module_directory=g_tempmod_dir)
            result = my_template.render(nav=self.create_navbar(False), root_url=g_root_url)
        except:
            result = self.error()
        return result

    @cherrypy.expose
    def logout(self):
        """Ends the logged in session."""
        try:
            # Get the logged in user.
            username = self.user_mgr.get_logged_in_user()
            if username is None:
                raise cherrypy.HTTPRedirect(LOGIN_URL)

            # Clear the session.
            self.user_mgr.clear_session()

            # Send the user back to the login screen.
            raise cherrypy.HTTPRedirect(LOGIN_URL)

        except cherrypy.HTTPRedirect as e:
            raise e
        except:
            result = self.error()
        return result

    @cherrypy.expose
    def index(self):
        """Renders the index (default) page."""
        return self.login()

    @cherrypy.expose
    def api(self, *args, **kw):
        """Endpoint for API calls."""
        response = ""
        try:
            # Get the logged in user.
            user_id = None
            username = self.user_mgr.get_logged_in_user()
            if username is not None:
                user_id, _, _ = self.user_mgr.retrieve_user(username)

            # The the API params.
            if cherrypy.request.method == "GET":
                params = kw
            elif len(kw) == 0:
                cl = cherrypy.request.headers['Content-Length']
                params = cherrypy.request.body.read(int(cl))
                params = json.loads(params)
            else:
                params = kw

            # Process the API request.
            if len(args) > 0:
                api_version = args[0]
                if api_version == '1.0':
                    api = Api.Api(g_root_dir, self.user_mgr, user_id)
                    handled, response = api.handle_api_1_0_request(args[1:], params)
                    if not handled:
                        self.log_error("Failed to handle request: " + args[1:])
                        cherrypy.response.status = 400
                    else:
                        cherrypy.response.status = 200
                else:
                    self.log_error("Failed to handle request for api version " + api_version)
                    cherrypy.response.status = 400
            else:
                cherrypy.response.status = 400
        except Exception as e:
            response = str(e.args[0])
            self.log_error(response)
            cherrypy.response.status = 500
        except:
            cherrypy.response.status = 500
        return response


def main():
    global g_root_dir
    global g_root_url
    global g_app

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

    user_mgr = UserMgr.UserMgr(g_root_dir)
    g_app = StatusWeb(user_mgr)

    cherrypy.tools.statusweb_auth = cherrypy.Tool('before_handler', check_auth)

    conf = {
        '/':
        {
            'tools.staticdir.root': g_root_dir,
            'tools.statusweb_auth.on': True,
            'tools.sessions.on': True,
            'tools.sessions.name': 'statusweb_auth',
            'tools.sessions.timeout': 129600,
            'tools.secureheaders.on': True
        },
        '/css':
        {
            'tools.staticdir.on': True,
            'tools.staticdir.dir': 'css'
        },
        '/js':
        {
            'tools.staticdir.on': True,
            'tools.staticdir.dir': 'js'
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

if __name__ == "__main__":
    main()
