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
import logging
import os
import signal
import sys
import bcrypt
import cherrypy
import mako
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
    """Class containing the URL handlers."""

    def __init__(self):
        super(StatusWeb, self).__init__()
        self.database = StatusDb.MongoDatabase(g_root_dir)

    def terminate(self):
        """Destructor"""
        logging.info("Terminating...")

    @staticmethod
    def create_navbar(logged_in=True):
        """Helper function for building the navigation bar."""
        navbar_str = "<nav>\n\t<ul>\n"
        navbar_str += "\t\t<li><a href=\"https://github.com/msimms/ComputerStatus/\">GitHub</a></li>\n"
        if logged_in is True:
            navbar_str += "\t\t<li><a href=\"" + g_root_url + "/dashboard/\">Dashboard</a></li>\n"
        navbar_str += "\t</ul>\n</nav>"
        return navbar_str

    @cherrypy.expose
    def error(self, error_str=None):
        """Renders the error page."""

        try:
            cherrypy.response.status = 500
            error_html_file = os.path.join(g_root_dir, 'html', 'error.html')
            my_template = Template(filename=error_html_file, module_directory=g_tempmod_dir)
            if error_str is None:
                error_str = "Internal Error."
        except:
            cherrypy.log.error("Unhandled exception in error().")
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

            statuses = self.database.retrieve_status(device_id)
            if statuses is not None and statuses.count() > 0:
                last_status = statuses[statuses.count() - 1]

                if 'cpu - percent' in last_status:
                    table_str += "\t\t<td>Current CPU Utilization</td><td>" + str(last_status['cpu - percent']) + "%</td><tr>\n"
                if 'cpu - temperature' in last_status:
                    table_str += "\t\t<td>Current CPU Temperature</td><td>" + str(last_status['cpu - temperature']) + degree_sign + "C</td><tr>\n"
                if 'virtual memory - percent' in last_status:
                    table_str += "\t\t<td>Current RAM Utilization</td><td>" + str(last_status['virtual memory - percent']) + "%</td><tr>\n"
                if 'gpu - percent' in last_status:
                    table_str += "\t\t<td>Current GPU Utilization</td><td>" + str(last_status['gpu - percent']) + "%</td><tr>\n"
                if 'gpu - temperature' in last_status:
                    table_str += "\t\t<td>Current GPU Temperature</td><td>" + str(last_status['gpu - temperature']) + degree_sign + "C</td><tr>\n"
                if 'network - bytes sent' in last_status:
                    table_str += "\t\t<td>Bytes Sent</td><td>" + str(last_status['network - bytes sent']) + " Bytes </td><tr>\n"
                if 'network - bytes received' in last_status:
                    table_str += "\t\t<td>Bytes Received</td><td>" + str(last_status['network - bytes received']) + " Bytes </td><tr>\n"

            table_str += "\t</table>\n"

            device_html_file = os.path.join(g_root_dir, 'html', 'device.html')
            my_template = Template(filename=device_html_file, module_directory=g_tempmod_dir)
            return my_template.render(nav=self.create_navbar(), root_url=g_root_url, title=title_str, device_id=device_id, table=table_str)
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
            user_id, _, _ = self.database.retrieve_user(username)
            if user_id is None:
                cherrypy.log.error('Unknown user ID', 'EXEC', logging.ERROR)
                raise cherrypy.HTTPRedirect("/dashboard")

            # Make sure the device ID is real.
            device_status = self.database.retrieve_status(device_id)
            if device_status.count() == 0:
                cherrypy.log.error('Unknown device ID', 'EXEC', logging.ERROR)
                raise cherrypy.HTTPRedirect("/dashboard")

            # Add the device id to the database.
            self.database.claim_device(user_id, device_id)

            # Refresh the dashboard page.
            raise cherrypy.HTTPRedirect("/dashboard")
        except cherrypy.HTTPRedirect as e:
            raise e
        except:
            cherrypy.log.error('Unhandled exception in dashboard', 'EXEC', logging.WARNING)
        return ""

    @cherrypy.expose
    def set_name_device(self, device_id, name):
        try:
            # Get the logged in user.
            username = cherrypy.session.get(SESSION_KEY)
            if username is None:
                raise cherrypy.HTTPRedirect("/login")

            # Get the details of the logged in user.
            user_id, _, _ = self.database.retrieve_user(username)
            if user_id is None:
                cherrypy.log.error('Unknown user ID', 'EXEC', logging.ERROR)
                raise cherrypy.HTTPRedirect("/dashboard")

            # Get the user's devices.
            devices = self.database.retrieve_user_devices(user_id)
            if not device_id in devices:
                cherrypy.log.error('Unknown device ID', 'EXEC', logging.ERROR)
                raise cherrypy.HTTPRedirect("/dashboard")

            # Add the device id to the database.
            self.database.create_device_name(device_id, name)

            # Refresh the dashboard page.
            raise cherrypy.HTTPRedirect("/dashboard")
        except cherrypy.HTTPRedirect as e:
            raise e
        except:
            cherrypy.log.error('Unhandled exception in dashboard', 'EXEC', logging.WARNING)
        return ""

    @cherrypy.expose
    def set_device_attribute_color(self, device_id, attribute, color):
        try:
            # Get the logged in user.
            username = cherrypy.session.get(SESSION_KEY)
            if username is None:
                raise cherrypy.HTTPRedirect("/login")

            # Get the details of the logged in user.
            user_id, _, _ = self.database.retrieve_user(username)
            if user_id is None:
                cherrypy.log.error('Unknown user ID', 'EXEC', logging.ERROR)
                raise cherrypy.HTTPRedirect("/dashboard")

            # Get the user's devices.
            devices = self.database.retrieve_user_devices(user_id)
            if not device_id in devices:
                cherrypy.log.error('Unknown device ID', 'EXEC', logging.ERROR)
                raise cherrypy.HTTPRedirect("/dashboard")

            # Add the device id to the database.
            self.database.create_device_attribute_color(device_id, attribute, color)

            # Refresh the dashboard page.
            raise cherrypy.HTTPRedirect("/dashboard")
        except cherrypy.HTTPRedirect as e:
            raise e
        except:
            cherrypy.log.error('Unhandled exception in dashboard', 'EXEC', logging.WARNING)
        return ""

    @cherrypy.expose
    @require()
    def dashboard(self, *args, **kw):
        """Page for displaying the devices owned by a particular user."""

        try:
            # Get the logged in user.
            username = cherrypy.session.get(SESSION_KEY)
            if username is None:
                raise cherrypy.HTTPRedirect("/login")

            # Get the details of the logged in user.
            user_id, _, _ = self.database.retrieve_user(username)
            if user_id is None:
                cherrypy.log.error('Unknown user ID', 'EXEC', logging.ERROR)
                raise cherrypy.HTTPRedirect("/login")

            # Get the user's devices.
            devices = self.database.retrieve_user_devices(user_id)

            # Render a table containing the user's devices.
            device_table_str = "\t<table>\n"
            device_table_str += "\t\t<td><b>Name</b></td><td><b>Device ID</b></td><tr>\n"
            if devices is not None:
                for device in devices:
                    device_id_str = str(device)
                    device_name = self.database.retrieve_device_name(device_id_str)
                    if device_name is None:
                        device_name = ""
                    device_table_str += "\t\t<td>" + device_name + "</td><td><a href=\"" + g_root_url + "/device/" + device_id_str + "\">" + device_id_str + "</a></td><tr>\n"
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

        _, db_hash1, _ = self.database.retrieve_user(email)
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
        userhash = bcrypt.hashpw(password1.encode('utf-8'), salt)
        if not self.database.create_user(email, realname, userhash):
            return False, "An internal error was encountered when creating the user."

        return True, "The user was created."

    @cherrypy.expose
    def submit_login(self, *args, **kw):
        """Processes a login."""

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

    @cherrypy.expose
    def submit_new_login(self, email, realname, password1, password2, *args, **kw):
        """Creates a new login."""

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

    @cherrypy.expose
    def login(self):
        """Renders the login page."""

        try:
            login_html_file = os.path.join(g_root_dir, 'html', 'login.html')
            my_template = Template(filename=login_html_file, module_directory=g_tempmod_dir)
            result = my_template.render(nav=self.create_navbar(False), root_url=g_root_url)
        except:
            result = self.error()
        return result

    @cherrypy.expose
    def create_login(self):
        """Renders the create login page."""

        try:
            create_login_html_file = os.path.join(g_root_dir, 'html', 'create_login.html')
            my_template = Template(filename=create_login_html_file, module_directory=g_tempmod_dir)
            result = my_template.render(nav=self.create_navbar(False), root_url=g_root_url)
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
            if len(args) > 0:
                api_version = args[0]
                if api_version == '1.0':
                    api = StatusApi.StatusApi(g_root_dir)
                    handled, response = api.handle_api_1_0_request(args[1:], kw)
                    if not handled:
                        cherrypy.response.status = 400
                    else:
                        cherrypy.response.status = 200
                else:
                    cherrypy.response.status = 400
            else:
                cherrypy.response.status = 400
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

    g_app = StatusWeb()

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
