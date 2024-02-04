# Copyright 2023 Michael J Simms

import argparse
import cherrypy
import json
import logging
import os
import signal
import sys
import traceback

import App
import InputChecker

from urllib.parse import parse_qs

SESSION_COOKIE = 'session_cookie'

g_front_end = None
g_session_mgr = None

def signal_handler(signal, frame):
    global g_front_end

    print("Exiting...")
    if g_front_end is not None:
        g_front_end.terminate()
    sys.exit(0)

@cherrypy.tools.register('before_finalize', priority=60)
def secureheaders():
    headers = cherrypy.response.headers
    headers['X-Frame-Options'] = 'DENY'
    headers['X-XSS-Protection'] = '1; mode=block'
    headers['Content-Security-Policy'] = "default-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com https://*.googleapis.com;"\
        "script-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com https://*.googleapis.com https://maps.gstatic.com;"\
        "object-src 'self';"\
        "font-src 'self' https://fonts.gstatic.com;"\
        "style-src 'self' 'unsafe-inline' 'unsafe-eval' https://cdnjs.cloudflare.com https://*.googleapis.com;"\
        "img-src 'self' *;"

def get_verb_path_params_and_cookie(env):
    """Gets all the thigns we need from an HTTP request."""

    verb = env['REQUEST_METHOD']
    path = env['REQUEST_URI'].split('/')[2:] # Don't need the first part of the path
    params = {}
    cookie = None

    # Look for our custom session cookie.
    if 'HTTP_COOKIE' in env:
        cookie_list_str = env['HTTP_COOKIE']
        cookie_list = cookie_list_str.split('; ')
        for temp_cookie in cookie_list:
            cookie_index = temp_cookie.find(SESSION_COOKIE)
            if cookie_index == 0:
                cookie = temp_cookie[len(SESSION_COOKIE) + 1:]

    # Parse the path and read any params.
    num_path_elems = len(path)
    if num_path_elems > 0:

        # GET requests will have the parameters in the URL.
        if verb == 'GET' or verb == 'DELETE':

            # Split off the params from a GET request.
            method_and_params = path[num_path_elems - 1].split('?')
            path[num_path_elems - 1] = method_and_params[0]

            # Did we find any parameters?
            if len(method_and_params) > 1:
                temp_params = parse_qs(method_and_params[1])
                for k in temp_params:
                    params[k] = (temp_params[k])[0]

        # POST requests will have the parameters in the body.
        elif verb == 'POST':
            temp_params = env['wsgi.input'].read()
            if len(temp_params) > 0:
                params = json.loads(temp_params)

    return verb, path, params, cookie

def do_auth_check(f):
    """Function decorator for endpoints that require the user to be logged in."""

    def auth_check(*args, **kwargs):
        global g_session_mgr

        # Extract the things we need from the request.
        env = args[0]
        _, _, _, cookie = get_verb_path_params_and_cookie(env)
        if g_session_mgr.get_logged_in_username_from_cookie(cookie) is not None:

            # User had a valid session token, so set it, do the request, and clear.
            g_session_mgr.set_current_session(cookie)
            response = f(*args, **kwargs)
            g_session_mgr.clear_current_session()

        # User does not have a valid session token, redirect to the login page.
        else:
            global g_front_end

            start_response = args[1]
            content = g_front_end.backend.login()
            start_response('401 Unauthorized', [])
            response = [content.encode('utf-8')]
 
        return response

    return auth_check

def do_session_check(f):
    """Function decorator for endpoints that where logging in is optional."""

    def session_check(*args, **kwargs):
        global g_session_mgr

        # Extract the things we need from the request.
        env = args[0]
        _, _, _, cookie = get_verb_path_params_and_cookie(env)

        # User had a valid session token, so set it, do the request, and clear.
        if cookie is not None:
            g_session_mgr.set_current_session(cookie)
        response = f(*args, **kwargs)
        g_session_mgr.clear_current_session()
 
        return response

    return session_check

def handle_error(start_response, error_code):
    """Renders the error page."""
    global g_front_end

    content = g_front_end.error().encode('utf-8')
    headers = [('Content-type', 'text/html; charset=utf-8')]
    start_response(str(error_code), headers)
    g_session_mgr.clear_current_session() # Housekeeping
    return [content]

def handle_error_403(start_response):
    """Renders the error page."""
    return handle_error(start_response, '403 Forbidden')

def handle_error_404(start_response):
    """Renders the error page."""
    return handle_error(start_response, '404 Not Found')

def handle_error_500(start_response):
    """Renders the error page."""
    return handle_error(start_response, '500 Internal Server Error')

def handle_redirect_exception(url, start_response):
    """Returns the redirect response."""
    start_response('302 Found', [('Location', url)])
    return []

def handle_dynamic_page_request(env, start_response, content, mime_type='text/html; charset=utf-8'):
    """Utility function called for each page handler."""
    """Makes sure the response is encoded correctly and that the headers are set correctly."""

    # Perform the page logic and encode the response.
    content = content.encode('utf-8')

    # Build the response headers.
    headers = []
    if mime_type is not None:
        headers.append(('Content-type', mime_type))

    # Return the response headers.
    start_response('200 OK', headers)

    # Return the page contents.
    return [content]

def handle_static_file_request(start_response, dir, file_name, mime_type):
    """Utility function called for each static resource request."""

    # Sanity checks.
    if [start_response, dir, file_name, mime_type].count(None) > 0:
        return handle_error_404(start_response)
    if dir.find('..') != -1:
        return handle_error_404(start_response)
    if file_name.find('..') != -1:
        return handle_error_404(start_response)

    # Clean up the provided file name. A leading slash will screw everything up.
    if file_name[0] == '/':
        file_name = file_name[1:]

    # Calculate the local file name.
    root_dir = os.path.dirname(os.path.abspath(__file__))
    local_file_name = os.path.join(root_dir, dir, file_name)

    # Sanity check the local file.
    if not InputChecker.is_safe_path(local_file_name):
        return handle_error_403(start_response)

    # Read and return the file.
    if os.path.exists(local_file_name):
        with open(local_file_name, "rb") as in_file:
            content = in_file.read()
            headers = [('Content-type', mime_type)]
            start_response('200 OK', headers)
            return [content]

    # Something went wrong. Return an error.
    headers = [('Content-type', 'text/plain; charset=utf-8')]
    start_response('404 Not Found', headers)
    return []

def log_error(log_str):
    """Writes an error message to the log file."""
    logger = logging.getLogger()
    logger.error(log_str)

def css(env, start_response):
    """Returns the CSS page."""
    try:
        return handle_static_file_request(start_response, "css", env['PATH_INFO'], 'text/css')
    except:
        # Log the error and then fall through to the error page response.
        log_error(traceback.format_exc())
        log_error(sys.exc_info()[0])
    return handle_error_500(start_response)

def js(env, start_response):
    """Returns the JS page."""
    try:
        return handle_static_file_request(start_response, "js", env['PATH_INFO'], 'text/html')
    except:
        # Log the error and then fall through to the error page response.
        log_error(traceback.format_exc())
        log_error(sys.exc_info()[0])
    return handle_error_500(start_response)

def media(env, start_response):
    """Returns media files (icons, etc.)."""
    try:
        return handle_static_file_request(start_response, "media", env['PATH_INFO'], 'text/html')
    except:
        # Log the error and then fall through to the error page response.
        log_error(traceback.format_exc())
        log_error(sys.exc_info()[0])
    return handle_error_500(start_response)

def error(env, start_response):
    """Renders the error page."""
    global g_front_end

    try:
        return handle_dynamic_page_request(env, start_response, g_front_end.backend.render_error())
    except App.RedirectException as e:
        return handle_redirect_exception(e.url, start_response)
    except:
        # Log the error and then fall through to the error page response.
        log_error(traceback.format_exc())
        log_error(sys.exc_info()[0])
    return handle_error_500(start_response)

@do_session_check
def device(env, start_response):
    """Renders the map page for a single device."""
    global g_front_end

    try:
        device_str = env['PATH_INFO']
        device_str = device_str[1:]
        return handle_dynamic_page_request(env, start_response, g_front_end.backend.device(device_str))
    except App.RedirectException as e:
        return handle_redirect_exception(e.url, start_response)
    except:
        # Log the error and then fall through to the error page response.
        log_error(traceback.format_exc())
        log_error(sys.exc_info()[0])
    return handle_error_500(start_response)

@do_auth_check
def dashboard(env, start_response):
    """Renders the user's dashboard page."""
    global g_front_end

    try:
        return handle_dynamic_page_request(env, start_response, g_front_end.backend.profile())
    except App.RedirectException as e:
        return handle_redirect_exception(e.url, start_response)
    except:
        # Log the error and then fall through to the error page response.
        log_error(traceback.format_exc())
        log_error(sys.exc_info()[0])
    return handle_error_500(start_response)

@do_auth_check
def settings(env, start_response):
    """Renders the user's settings page."""
    global g_front_end

    try:
        return handle_dynamic_page_request(env, start_response, g_front_end.backend.settings())
    except App.RedirectException as e:
        return handle_redirect_exception(e.url, start_response)
    except:
        # Log the error and then fall through to the error page response.
        log_error(traceback.format_exc())
        log_error(sys.exc_info()[0])
    return handle_error_500(start_response)

@do_session_check
def login(env, start_response):
    """Renders the login page."""
    global g_front_end

    try:
        return handle_dynamic_page_request(env, start_response, g_front_end.backend.login())
    except App.RedirectException as e:
        return handle_redirect_exception(e.url, start_response)
    except:
        # Log the error and then fall through to the error page response.
        log_error(traceback.format_exc())
        log_error(sys.exc_info()[0])
    return handle_error_500(start_response)

@do_session_check
def create_login(env, start_response):
    """Renders the create login page."""
    global g_front_end

    try:
        return handle_dynamic_page_request(env, start_response, g_front_end.backend.create_login())
    except:
        # Log the error and then fall through to the error page response.
        log_error(traceback.format_exc())
        log_error(sys.exc_info()[0])
    return handle_error_500(start_response)

def logout(env, start_response):
    """Ends the logged in session."""
    global g_session_mgr

    _, _, _, cookie = get_verb_path_params_and_cookie(env)
    g_session_mgr.invalidate_session_token(cookie)
    return handle_dynamic_page_request(env, start_response, g_front_end.backend.login())

def api(env, start_response):
    """Endpoint for API calls."""
    global g_front_end

    try:
        # Extract the things we need from the request.
        verb, path, params, cookie = get_verb_path_params_and_cookie(env)
        g_session_mgr.set_current_session(cookie)

        # Handle the API request.
        content, response_code = g_front_end.api_internal(verb, tuple(path), params, cookie)

        # Housekeeping.
        g_session_mgr.clear_current_session()

        # Return the response headers.
        if response_code == 200:
            headers = []
            headers.append(('Content-type', 'application/json'))

            content = content.encode('utf-8')
            start_response('200 OK', headers)
            return [content]
        elif response_code == 404:
            return handle_error_404(start_response)
    except:
        # Log the error and then fall through to the error page response.
        log_error(traceback.format_exc())
        log_error(sys.exc_info()[0])
    return handle_error_500(start_response)

@do_session_check
def index(env, start_response):
    """Renders the index page."""
    return login(env, start_response)

def create_server(port_num):
    """Returns a cherrypy server object."""

    # Instantiate a new server object.
    server = cherrypy._cpserver.Server()

    # Configure the server object.
    server.socket_host = "0.0.0.0"
    server.socket_port = port_num
    server.thread_pool = 30

    # Subscribe this server.
    server.subscribe()

    return server

def main():
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

    # Register the signal handler.
    signal.signal(signal.SIGINT, signal_handler)

    try:
        # Create all the objects that actually implement the functionality.
        root_dir = os.path.dirname(os.path.abspath(__file__))

        # The directory for session objects.
        session_dir = os.path.join(root_dir, 'sessions')
        if not os.path.exists(session_dir):
            os.makedirs(session_dir)

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

        # Mount the application.
        cherrypy.tree.graft(css, "/css")
        cherrypy.tree.graft(js, "/js")
        cherrypy.tree.graft(media, "/media")
        cherrypy.tree.graft(device, "/device")
        cherrypy.tree.graft(dashboard, "/dashboard")
        cherrypy.tree.graft(settings, "/settings")
        cherrypy.tree.graft(login, "/login")
        cherrypy.tree.graft(create_login, "/create_login")
        cherrypy.tree.graft(logout, "/logout")
        cherrypy.tree.graft(api, "/api")
        cherrypy.tree.graft(index, "/")

        # Unsubscribe the default server.
        cherrypy.server.unsubscribe()

        # Create the cherrypy object.
        cherrypy.config.update(conf)
        app = cherrypy.tree.mount(g_front_end, '/')
        app.merge(conf)

        # Instantiate a new server object.
        servers = []
        port_num = args.port
        num_servers = 1
        if num_servers <= 0:
            num_servers = 1
        for i in range(0, num_servers):
            servers.append(create_server(port_num + i))

        cherrypy.config.update(conf)
        cherrypy.engine.start()
        cherrypy.engine.block()
    except Exception as e:
        print(e)
        sys.exit(1)

if __name__ == "__main__":
    main()
