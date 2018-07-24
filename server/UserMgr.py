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

import bcrypt
import SessionMgr
import StatusDb


MIN_PASSWORD_LEN  = 8

class UserMgr(object):
    """Class for managing users"""

    def __init__(self, root_dir):
        self.database = StatusDb.MongoDatabase(root_dir)
        self.session_mgr = SessionMgr.SessionMgr()
        super(UserMgr, self).__init__()

    def terminate(self):
        """Destructor"""
        self.database = None

    def get_logged_in_user(self):
        """Returns the username associated with the current session."""
        return self.session_mgr.get_logged_in_user()

    def get_logged_in_user_from_cookie(self, auth_cookie):
        """Returns the username associated with the specified authentication cookie."""
        return self.session_mgr.get_logged_in_user_from_cookie(auth_cookie)

    def create_new_session(self, username):
        """Starts a new session."""
        return self.session_mgr.create_new_session(username)

    def clear_session(self):
        """Ends the current session."""
        self.session_mgr.clear_session()

    def authenticate_user(self, email, password):
        """Validates a user against the credentials in the database."""
        if self.database is None:
            raise Exception("No database.")
        if len(email) == 0:
            raise Exception("An email address not provided.")
        if len(password) < MIN_PASSWORD_LEN:
            raise Exception("The password is too short.")

        _, db_hash1, _ = self.database.retrieve_user(email)
        if db_hash1 is None:
            raise Exception("The user could not be found.")
        db_hash2 = bcrypt.hashpw(password.encode('utf-8'), db_hash1.encode('utf-8'))
        if db_hash1 != db_hash2:
            raise Exception("The password is invalid.")
        return True

    def create_user(self, email, realname, password1, password2):
        """Adds a user to the database."""
        if self.database is None:
            raise Exception("No database.")
        if len(email) == 0:
            raise Exception("An email address not provided.")
        if len(realname) == 0:
            raise Exception("Name not provided.")
        if len(password1) < MIN_PASSWORD_LEN:
            raise Exception("The password is too short.")
        if password1 != password2:
            raise Exception("The passwords do not match.")
        if self.database.retrieve_user(email) is None:
            raise Exception("The user already exists.")

        salt = bcrypt.gensalt()
        computed_hash = bcrypt.hashpw(password1.encode('utf-8'), salt)
        if not self.database.create_user(email, realname, computed_hash):
            raise Exception("An internal error was encountered when creating the user.")

        return True

    def retrieve_user(self, email):
        """Retrieve method for a user."""
        if self.database is None:
            raise Exception("No database.")
        if email is None or len(email) == 0:
            raise Exception("Bad parameter.")
        return self.database.retrieve_user(email)

    def update_user_email(self, user_id, email, realname):
        """Updates a user's database entry."""
        if self.database is None:
            raise Exception("No database.")
        if user_id is None:
            raise Exception("Unexpected empty object: user_id.")
        if len(email) == 0:
            raise Exception("Email address not provided.")
        if len(realname) == 0:
            raise Exception("Name not provided.")

        if not self.database.update_user(user_id, email, realname, None):
            raise Exception("An internal error was encountered when updating the user.")
        return True

    def update_user_password(self, user_id, email, realname, password1, password2):
        """Updates a user's password."""
        if self.database is None:
            raise Exception("No database.")
        if user_id is None:
            raise Exception("Unexpected empty object: user_id.")
        if len(email) == 0:
            raise Exception("Email address not provided.")
        if len(realname) == 0:
            raise Exception("Name not provided.")
        if len(password1) < MIN_PASSWORD_LEN:
            raise Exception("The password is too short.")
        if password1 != password2:
            raise Exception("The passwords do not match.")

        salt = bcrypt.gensalt()
        computed_hash = bcrypt.hashpw(password1.encode('utf-8'), salt)
        if not self.database.update_user(user_id, email, realname, computed_hash):
            raise Exception("An internal error was encountered when updating the user.")
        return True

    def delete_user(self, user_id):
        """Removes a user from the database."""
        if self.database is None:
            raise Exception("No database.")
        if user_id is None or len(user_id) == 0:
            raise Exception("Bad parameter.")

        # Delete data from the user's devices, as well as the associated attributes.
        user_devices = self.database.retrieve_user_devices(user_id)
        for user_device in user_devices:
            self.database.delete_status(user_device)
            self.database.delete_device_attributes(user_device)
        return self.database.delete_user(user_id)
