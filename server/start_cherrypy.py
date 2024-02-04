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
"""Main application, contains all web page handlers, written for CherryPy"""

import argparse
import json
import logging
import mako
import os
import signal
import sys
import cherrypy
import App
import SessionMgr
import UserMgr

from cherrypy.process.plugins import Daemonizer

ACCESS_LOG = 'access.log'
ERROR_LOG = 'error.log'
LOGIN_URL = '/login'

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
    headers['Content-Security-Policy'] = "default-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com;"\
        "script-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com;"\
        "object-src 'self';"\
        "font-src 'self';"\
        "style-src 'self' 'unsafe-inline' 'unsafe-eval' https://cdnjs.cloudflare.com;"\
        "img-src 'self' *;"

def check_auth(*args, **kwargs):
    global g_app

    # A tool that looks in config for 'auth.require'. If found and it is not None, a login
    # is required and the entry is evaluated as a list of conditions that the user must fulfill
    conditions = cherrypy.request.config.get('auth.require', None)
    if conditions is not None:
        requested_url = cherrypy.request.request_line.split()[1]
        requested_url_parts = requested_url.split('/')
        requested_url_parts = filter(lambda part: part != '', requested_url_parts)

        username = g_app.app.user_mgr.get_logged_in_user()
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

    def __init__(self, app):
        self.app = app
        super(StatusWeb, self).__init__()

    def terminate(self):
        """Destructor"""
        logging.info("Terminating...")
        self.app.terminate()
        self.app = None

    def log_error(self, log_str):
        """Writes an error message to the log file."""
        logger = logging.getLogger()
        logger.error(log_str)

    @cherrypy.expose
    def error(self, error_str=None):
        """Renders the error page."""
        try:
            cherrypy.response.status = 500
            return self.app.error(error_str)
        except:
            pass
        return self.app.error("")

    @cherrypy.expose
    def device(self, device_id, *args, **kw):
        """Page for displaying graphs about a particular device."""
        try:
            return self.app.device(device_id)
        except App.RedirectException as e:
            raise cherrypy.HTTPRedirect(e.url)
        except cherrypy.HTTPRedirect as e:
            raise e
        except:
            self.log_error('Unhandled exception in ' + StatusWeb.device.__name__)
        return ""

    @cherrypy.expose
    @require()
    def dashboard(self, *args, **kw):
        """Page for displaying the devices owned by a particular user."""
        try:
            return self.app.dashboard()
        except App.RedirectException as e:
            raise cherrypy.HTTPRedirect(e.url)
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
            return self.app.settings()
        except App.RedirectException as e:
            raise cherrypy.HTTPRedirect(e.url)
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
            return self.app.submit_login(email, password)
        except App.RedirectException as e:
            raise cherrypy.HTTPRedirect(e.url)
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
            return self.app.submit_new_login(email, realname, password1, password2)
        except App.RedirectException as e:
            raise cherrypy.HTTPRedirect(e.url)
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
            return self.app.login()
        except App.RedirectException as e:
            raise cherrypy.HTTPRedirect(e.url)
        except cherrypy.HTTPRedirect as e:
            raise e
        except:
            return self.error()
        return self.error()

    @cherrypy.expose
    def create_login(self):
        """Renders the create login page."""
        try:
            return self.app.create_login()
        except Exception as e:
            error_msg = str(e.args[0])
            self.log_error(error_msg)
            return self.error(error_msg)
        except:
            return self.error()
        return self.error()

    @cherrypy.expose
    def logout(self):
        """Ends the logged in session."""
        try:
            return self.app.logout()
        except App.RedirectException as e:
            raise cherrypy.HTTPRedirect(e.url)
        except cherrypy.HTTPRedirect as e:
            raise e
        except:
            return self.error()
        return self.error()

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
            username = self.app.user_mgr.get_logged_in_user()
            if username is not None:
                user_id, _, _ = self.app.user_mgr.retrieve_user(username)

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
                    method = args[1:]
                    handled, response = self.app.api(user_id, method[0], params)
                    if not handled:
                        self.log_error("Failed to handle request: " + method[0])
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
    global g_app

    # Make sure we have a compatible version of python.
    if sys.version_info[0] < 3:
        print("This application requires python3.")
        sys.exit(1)

    # Parse command line options.
    parser = argparse.ArgumentParser()
    parser.add_argument("--debug", action="store_true", default=False, help="Prevents the app from going into the background", required=False)
    parser.add_argument("--disable_new_logins", action="store_true", default=False, help="Used to disable new login creation", required=False)
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
            root_url = "https://127.0.0.1:" + str(args.port)
        else:
            root_url = "http://127.0.0.1:" + str(args.port)
    else:
        if args.https:
            root_url = 'https://' + args.url
        else:
            root_url = 'http://' + args.url

        Daemonizer(cherrypy.engine).subscribe()

    if args.https:
        print("Running HTTPS....")
        cherrypy.server.ssl_module = 'builtin'
        cherrypy.server.ssl_certificate = args.cert
        print("Certificate File: " + args.cert)
        cherrypy.server.ssl_private_key = args.privkey
        print("Private Key File: " + args.privkey)

    signal.signal(signal.SIGINT, signal_handler)
    mako.collection_size = 100
    mako.directories = "templates"

    root_dir = os.path.dirname(os.path.abspath(__file__))
    user_mgr = UserMgr.UserMgr(root_dir, SessionMgr.CherryPySessionMgr())
    backend = App.App(user_mgr, root_dir, root_url, args.disable_new_logins)
    g_app = StatusWeb(backend)

    # The directory for session objects.
    session_dir = os.path.join(root_dir, 'sessions')
    if not os.path.exists(session_dir):
        os.makedirs(session_dir)

    cherrypy.tools.statusweb_auth = cherrypy.Tool('before_handler', check_auth)

    conf = {
        '/':
        {
            'tools.staticdir.root': root_dir,
            'tools.statusweb_auth.on': True,
            'tools.sessions.on': True,
            'tools.sessions.httponly': True,
            'tools.sessions.name': 'statusweb_auth',
            'tools.sessions.storage_type': 'file',
            'tools.sessions.storage_path': session_dir,
            'tools.sessions.timeout': 129600,
            'tools.sessions.locking': 'early',
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
