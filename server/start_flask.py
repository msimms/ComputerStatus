# -*- coding: utf-8 -*-
# 
# # MIT License
# 
# Copyright (c) 2023 Mike Simms
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
"""Main application, contains all web page handlers, written for Flask"""

import argparse
import functools
import json
import logging
import mako
import os
import signal
import sys
import traceback
import flask
import App
import SessionMgr
import UserMgr

g_flask_app = flask.Flask(__name__)
g_flask_app.secret_key = 'SvmkyMfFlMD2qdzUBvCq'
g_flask_app.url_map.strict_slashes = False
g_app = None

def signal_handler(signal, frame):
    global g_app

    print("Exiting...")
    if g_app is not None:
        g_app.terminate()
    sys.exit(0)

def terminate():
    """Destructor"""
    global g_app
    logging.info("Terminating...")
    g_app.terminate()
    g_app = None

def log_error(log_str):
    """Writes an error message to the log file."""
    logger = logging.getLogger()
    logger.error(log_str)

def login_required(function_to_protect):
    @functools.wraps(function_to_protect)
    def wrapper(*args, **kwargs):
        global g_app
        user = g_app.user_mgr.session_mgr.get_logged_in_username()
        if user:
            return function_to_protect(*args, **kwargs)
        return flask.redirect(flask.url_for('login'))
    return wrapper

@g_flask_app.errorhandler(404)
def page_not_found(e):
    global g_app
    return g_app.error("Page Not Found")

@g_flask_app.route('/css/<file_name>')
def css(file_name):
    """Returns the CSS page."""
    global g_app
    try:
        return flask.send_from_directory("css", file_name)
    except:
        g_app.log_error(traceback.format_exc())
        g_app.log_error(sys.exc_info()[0])
        g_app.log_error('Unhandled exception in ' + css.__name__)
    return g_app.render_error()

@g_flask_app.route('/js/<file_name>')
def js(file_name):
    """Returns the JS page."""
    global g_app
    try:
        return flask.send_from_directory("js", file_name)
    except:
        g_app.log_error(traceback.format_exc())
        g_app.log_error(sys.exc_info()[0])
        g_app.log_error('Unhandled exception in ' + js.__name__)
    return g_app.render_error()

@g_flask_app.route('/images/<file_name>')
def images(file_name):
    """Returns images."""
    global g_app
    try:
        return flask.send_from_directory("images", file_name)
    except:
        g_app.log_error(traceback.format_exc())
        g_app.log_error(sys.exc_info()[0])
        g_app.log_error('Unhandled exception in ' + images.__name__)
    return g_app.render_error()

@g_flask_app.route('/media/<file_name>')
def media(file_name):
    """Returns media files (icons, etc.)."""
    global g_app
    try:
        return flask.send_from_directory("media", file_name)
    except:
        g_app.log_error(traceback.format_exc())
        g_app.log_error(sys.exc_info()[0])
        g_app.log_error('Unhandled exception in ' + media.__name__)
    return g_app.render_error()

@g_flask_app.route('/error')
def error(error_str=None):
    """Renders the error page."""
    try:
        global g_app
        return g_app.error(error_str)
    except:
        pass
    return g_app.error("")

@g_flask_app.route('/device/<device_id>')
def device(device_id):
    """Page for displaying graphs about a particular device."""
    try:
        global g_app
        return g_app.device(device_id)
    except App.RedirectException as e:
        return flask.redirect(e.url, code=302)
    except:
        log_error('Unhandled exception in ' + device.__name__)
    return ""

@g_flask_app.route('/dashboard')
@login_required
def dashboard():
    """Page for displaying the devices owned by a particular user."""
    try:
        global g_app
        return g_app.dashboard()
    except App.RedirectException as e:
        return flask.redirect(e.url, code=302)
    except:
        log_error('Unhandled exception in ' + dashboard.__name__)
    return ""

@g_flask_app.route('/settings')
@login_required
def settings():
    """Renders the user's settings page."""
    try:
        global g_app
        return g_app.settings()
    except App.RedirectException as e:
        return flask.redirect(e.url, code=302)
    except:
        log_error('Unhandled exception in ' + settings.__name__)
    return error()

@g_flask_app.route('/submit_login', methods=(['POST']))
def submit_login():
    """Processes a login."""
    try:
        global g_app
        email = flask.request.form["email"]
        password = flask.request.form["password"]
        return g_app.submit_login(email, password)
    except App.RedirectException as e:
        return flask.redirect(e.url, code=302)
    except Exception as e:
        error_msg = 'Unable to authenticate the user. ' + str(e.args[0])
        log_error(error_msg)
        return error(error_msg)
    except:
        log_error('Unhandled exception in ' + submit_login.__name__)
    return error()

@g_flask_app.route('/submit_new_login')
def submit_new_login(email, realname, password1, password2):
    """Creates a new login."""
    try:
        global g_app
        return g_app.submit_new_login(email, realname, password1, password2)
    except App.RedirectException as e:
        return flask.redirect(e.url, code=302)
    except Exception as e:
        error_msg = 'Unable to create the user. ' + str(e.args[0])
        log_error(error_msg)
        return error(error_msg)
    except:
        log_error('Unhandled exception in ' + submit_new_login.__name__)
    return error()

@g_flask_app.route('/login')
def login():
    """Renders the login page."""
    try:
        global g_app
        return g_app.login()
    except App.RedirectException as e:
        return flask.redirect(e.url, code=302)
    except:
        log_error('Unhandled exception in ' + login.__name__)
    return error()

@g_flask_app.route('/create_login')
def create_login():
    """Renders the create login page."""
    try:
        global g_app
        return g_app.create_login()
    except Exception as e:
        error_msg = str(e.args[0])
        log_error(error_msg)
        return error(error_msg)
    except:
        log_error('Unhandled exception in ' + create_login.__name__)
    return error()

@g_flask_app.route('/logout')
def logout():
    """Ends the logged in session."""
    try:
        global g_app
        return g_app.logout()
    except App.RedirectException as e:
        return flask.redirect(e.url, code=302)
    except:
        log_error('Unhandled exception in ' + logout.__name__)
    return error()

@g_flask_app.route('/')
def index():
    """Renders the index (default) page."""
    return login()

@g_flask_app.route('/api/<version>/<method>', methods = ['GET','POST','DELETE'])
def api(version, method):
    """Endpoint for API calls."""
    global g_app
    response = ""
    code = 500
    try:
        # The the API params.
        if flask.request.method == 'GET':
            verb = "GET"
            params = flask.request.args
        elif flask.request.method == 'DELETE':
            verb = "DELETE"
            params = flask.request.args
        elif flask.request.data:
            verb = "POST"
            params = json.loads(flask.request.data)
        else:
            verb = "GET"
            params = ""

        # Get the logged in user.
        user_id = None
        username = g_app.user_mgr.get_logged_in_user()
        if username is not None:
            user_id, _, _ = g_app.user_mgr.retrieve_user(username)

        # Process the API request.
        if version == '1.0':
            handled, response = g_app.api(user_id, method, params)
            if not handled:
                response = "Failed to handle request: " + str(method)
                g_app.log_error(response)
                code = 400
            else:
                code = 200
        else:
            g_app.log_error("Failed to handle request for api version " + version)
            code = 400
    except Exception as e:
        response = str(e.args[0])
        g_app.log_error(response)
        code = 500
    except:
        code = 500
    return response, code
    
def main():
    global g_app
    global g_flask_app

    # Make sure we have a compatible version of python.
    if sys.version_info[0] < 3:
        print("This application requires python 3.")
        sys.exit(1)

    # Parse command line options.
    parser = argparse.ArgumentParser()
    parser.add_argument("--debug", action="store_true", default=False, help="Prevents the app from going into the background", required=False)
    parser.add_argument("--disable_new_logins", action="store_true", default=False, help="Used to disable new login creation", required=False)
    parser.add_argument("--port", type=int, default=8282, help="Port on which to listen", required=False)
    parser.add_argument("--https", action="store_true", default=False, help="Runs the app as HTTPS", required=False)
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

    signal.signal(signal.SIGINT, signal_handler)
    mako.collection_size = 100
    mako.directories = "templates"

    root_dir = os.path.dirname(os.path.abspath(__file__))
    user_mgr = UserMgr.UserMgr(root_dir, SessionMgr.FlaskSessionMgr())
    g_app = App.App(user_mgr, root_dir, root_url, args.disable_new_logins)
    g_flask_app.run(host="127.0.0.1", port=args.port, debug=args.debug)

    # The direcory for session objects.
    session_dir = os.path.join(root_dir, 'sessions')
    if not os.path.exists(session_dir):
        os.makedirs(session_dir)

if __name__ == "__main__":
    main()
