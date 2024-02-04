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
"""Manages login sessions."""

import cherrypy
import flask
import logging
import os
import time
import uuid

import StatusDb

SESSION_KEY = '_computerstatus_username'

class SessionMgr(object):
    """Class for managing sessions. A user may have more than one session"""

    def __init__(self):
        super(SessionMgr, self).__init__()

    def log_error(self, log_str):
        """Writes an error message to the log file."""
        logger = logging.getLogger()
        logger.error(log_str)

    def get_logged_in_username(self):
        """Returns the username associated with the current session."""
        return None

    def get_logged_in_username_from_cookie(self, auth_cookie):
        """Returns the username associated with the specified authentication cookie."""
        return None

    def create_new_session(self, username):
        """Starts a new session."""
        return None, None

    def set_current_session(self, cookie):
        """Accessor method for setting the cookie associated with the current session."""
        pass

    def clear_current_session(self):
        """Ends the current session."""
        pass

    def invalidate_session_token(self, session_cookie):
        """Removes the session token from the cache, and anywhere else it might be stored."""
        pass

    def session_dir(self, root_dir):
        """Returns the directory to be used for session storage."""
        session_dir = os.path.join(root_dir, 'session_cache')
        if not os.path.exists(session_dir):
            os.makedirs(session_dir)
        return session_dir

class CustomSessionMgr(SessionMgr):
    """Custom session manager, avoids the logic provided by the framework. Goal is a high performance session manager."""

    def __init__(self, root_dir):
        super(SessionMgr, self).__init__()
        self.current_session_cookie = None
        self.database = StatusDb.MongoDatabase(root_dir)

    def get_logged_in_username(self):
        """Returns the username associated with the current session."""
        if self.current_session_cookie is None:
            return None
        return self.get_logged_in_username_from_cookie(self.current_session_cookie)

    def get_logged_in_username_from_cookie(self, session_cookie):
        """Returns the username associated with the specified session cookie."""
        session_user, session_expiry = self.database.retrieve_session_data(session_cookie)
        if session_user is not None and session_expiry is not None:

            # Is the token still valid.
            now = time.time()
            if now < session_expiry:
                return session_user

            # Token is expired, so delete it.
            self.database.delete_session_token(session_cookie)
        return None

    def create_new_session(self, username):
        """Starts a new session. Returns the session cookie and it's expiry date."""
        session_cookie = str(uuid.uuid4())
        expiry = int(time.time() + 90.0 * 86400.0)
        if self.database.create_session_token(session_cookie, username, expiry):
            self.current_session_cookie = session_cookie
            return session_cookie, expiry
        return None, None

    def set_current_session(self, cookie):
        """Accessor method for setting the cookie associated with the current session."""
        self.current_session_cookie = cookie

    def clear_current_session(self):
        """Ends the current session."""
        self.current_session_cookie = None

    def invalidate_session_token(self, session_cookie):
        """Removes the session token from the cache, and anywhere else it might be stored."""
        self.database.delete_session_token(session_cookie)

class CherryPySessionMgr(SessionMgr):
    """Class for managing sessions when using the cherrypy framework. A user may have more than one session."""

    def __init__(self):
        super(SessionMgr, self).__init__()

    def get_logged_in_username(self):
        """Returns the username associated with the current session."""
        try:
            user = cherrypy.session.get(SESSION_KEY)
        except AttributeError:
            self.log_error("cherrypy.session has not been instantiated.")
            user = None
        return user

    def get_logged_in_username_from_cookie(self, session_cookie):
        """Returns the username associated with the specified session cookie."""
        try:
            user = None
            cache_items = cherrypy.session.cache.items()
            for session_id, session in cache_items:
                if session_id == session_cookie:
                    session_user = session[0]
                    if SESSION_KEY in session_user:
                        user = session_user[SESSION_KEY]
        except AttributeError:
            self.log_error("cherrypy.session has not been instantiated.")
            user = None
        return user

    def create_new_session(self, username):
        """Starts a new session."""
        cherrypy.session.load()
        cherrypy.session.regenerate()
        cherrypy.session[SESSION_KEY] = cherrypy.request.login = username
        new_id = cherrypy.session.id
        expiry = int(time.time() + 90.0 * 86400.0)
        return new_id, expiry

    def clear_current_session(self):
        """Ends the current session."""
        current_session = cherrypy.session
        current_session[SESSION_KEY] = None

class FlaskSessionMgr(SessionMgr):
    """Class for managing sessions when using the flask framework. A user may have more than one session."""

    def __init__(self):
        super(SessionMgr, self).__init__()

    def get_logged_in_username(self):
        """Returns the username associated with the current session."""
        if SESSION_KEY in flask.session:
            return flask.session[SESSION_KEY]
        return None

    def get_logged_in_username_from_cookie(self, session_cookie):
        """Returns the username associated with the specified authentication cookie."""
        pass

    def create_new_session(self, username):
        """Starts a new session."""
        flask.session[SESSION_KEY] = username
        expiry = int(time.time() + 90.0 * 86400.0)
        return None, expiry

    def clear_current_session(self):
        """Ends the current session."""
        flask.session.pop(SESSION_KEY, None)
        flask.session.clear()
