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

import cherrypy

SESSION_KEY = '_computerstatus_username'

class SessionMgr(object):
    """Class for managing sessions. A user may have more than one session"""

    def __init__(self):
        super(SessionMgr, self).__init__()

    def get_logged_in_user(self):
        """Returns the username associated with the current session."""
        return cherrypy.session.get(SESSION_KEY)

    def get_logged_in_user_from_cookie(self, auth_cookie):
        """Returns the username associated with the specified authentication cookie."""
        cache_items = cherrypy.session.cache.items()
        for session_id, session in cache_items:
            if session_id == auth_cookie:
                session_user = session[0]
                if SESSION_KEY in session_user:
                    return session_user[SESSION_KEY]
        return None

    def create_new_session(self, username):
        """Starts a new session."""
        cherrypy.session.load()
        cherrypy.session.regenerate()
        cherrypy.session[SESSION_KEY] = cherrypy.request.login = username
        return cherrypy.session.id

    def clear_session(self):
        """Ends the current session."""
        sess = cherrypy.session
        sess[SESSION_KEY] = None
