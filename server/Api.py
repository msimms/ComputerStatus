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
"""API request handlers"""

import fractions
import inspect
import json
import os
import sys
import uuid
import InputChecker
import StatusDb
from urllib.parse import unquote_plus

currentdir = os.path.dirname(os.path.abspath(inspect.getfile(inspect.currentframe())))
parentdir = os.path.dirname(currentdir)
clientdir = os.path.join(parentdir, 'client')
sys.path.insert(0, clientdir)
import keys

# Keys associated with session management.
SESSION_TOKEN_KEY = "cookie"
SESSION_USER_KEY = "user"
SESSION_EXPIRY_KEY = "expiry"

# Keys associated with user management.
USERNAME_KEY = "username" # Login name for a user
USER_ID_KEY = "user_id" # Unique identifier for a user
PASSWORD_KEY = "password" # User's password
PASSWORD1_KEY = "password1" # User's password when creating an account
PASSWORD2_KEY = "password2" # User's confirmation password when creating an account
REALNAME_KEY = "realname" # User's real name

# For managing devices that report status.
DEVICE_ID_KEY = "device_id"
DEVICE_STATUS_TIMESTAMP_KEY = "datetime"
DEVICE_ATTRIBUTE_KEY = "attribute"
DEVICE_ATTRIBUTES_KEY = "attributes"
DEVICE_NAME_KEY = "name"

class Api(object):
    """Class for managing API messages."""

    def __init__(self, root_dir, user_mgr, user_id):
        super(Api, self).__init__()
        self.database = StatusDb.MongoDatabase(root_dir)
        self.user_mgr = user_mgr
        self.user_id = user_id

    def handle_login(self, values):
        """Called when an API message to login is received."""
        if self.user_id is not None:
            return True, ""

        # Required parameters.
        if USERNAME_KEY not in values:
            raise Exception("Username not specified.")
        if PASSWORD_KEY not in values:
            raise Exception("Password not specified.")

        # Decode and validate the required parameters.
        email = unquote_plus(values[USERNAME_KEY])
        if not InputChecker.is_email_address(email):
            raise Exception("Invalid email address.")
        password = unquote_plus(values[PASSWORD_KEY])

        # Validate the credentials.
        try:
            if not self.user_mgr.authenticate_user(email, password):
                raise Exception("Authentication failed.")
        except Exception as e:
            raise Exception(str(e))

        # Create session information for this new login.
        cookie, expiry = self.user_mgr.create_new_session(email)
        if not cookie:
            raise Exception("Session cookie not generated.")
        if not expiry:
            raise Exception("Session expiry not generated.")

        # Encode the session info.
        session_data = {}
        session_data[SESSION_TOKEN_KEY] = cookie
        session_data[SESSION_EXPIRY_KEY] = expiry
        session_data[USER_ID_KEY] = str(self.user_mgr.get_logged_in_user_id())
        json_result = json.dumps(session_data, ensure_ascii=False)

        return True, json_result

    def handle_create_login(self, values):
        """Called when an API message to create an account is received."""
        if self.user_id is not None:
            raise Exception("Already logged in.")

        # Make sure this is allowed.
        # Creating a new login can be disabled for security reasons, testing, etc.
        if self.config.is_create_login_disabled():
            raise Exception("Creating a new login is currently disabled.")

        # Required parameters.
        if USERNAME_KEY not in values:
            raise Exception("Username not specified.")
        if REALNAME_KEY not in values:
            raise Exception("Real name not specified.")
        if PASSWORD1_KEY not in values:
            raise Exception("Password not specified.")
        if PASSWORD2_KEY not in values:
            raise Exception("Password confirmation not specified.")

        # Decode and validate the required parameters.
        email = unquote_plus(values[USERNAME_KEY])
        if not InputChecker.is_email_address(email):
            raise Exception("Invalid email address.")
        realname = unquote_plus(values[REALNAME_KEY])
        if not InputChecker.is_valid_decoded_str(realname):
            raise Exception("Invalid name.")
        password1 = unquote_plus(values[PASSWORD1_KEY])
        password2 = unquote_plus(values[PASSWORD2_KEY])

        # Add the user to the database, should fail if the user already exists.
        try:
            if not self.user_mgr.create_user(email, realname, password1, password2, device_str):
                raise Exception("User creation failed.")
        except:
            raise Exception("User creation failed.")

        # The new user should start in a logged-in state, so generate session info.
        cookie, expiry = self.user_mgr.create_new_session(email)
        if not cookie:
            raise Exception("Session cookie not generated.")
        if not expiry:
            raise Exception("Session expiry not generated.")

        # Encode the session info.
        session_data = {}
        session_data[SESSION_TOKEN_KEY] = cookie
        session_data[SESSION_EXPIRY_KEY] = expiry
        session_data[USER_ID_KEY] = str(self.user_mgr.get_logged_in_user_id())
        json_result = json.dumps(session_data, ensure_ascii=False)

        return True, json_result

    def handle_login_status(self, values):
        """Called when an API message to check the login status in is received."""
        if self.user_id is None:
            raise Exception("Not logged in")
        return True, "Logged In"

    def handle_logout(self, values):
        """Ends the session for the specified user."""
        if self.user_id is None:
            raise Exception("Not logged in")

        # End the session
        self.user_mgr.clear_current_session()
        self.user_id = None
        return True, "Logged Out"

    def handle_create_status(self, status):
        """Called when new data is received. Sanitizes the data before storing it."""
        if DEVICE_ID_KEY not in status:
            raise Exception("device_id not specified.")
        if DEVICE_STATUS_TIMESTAMP_KEY not in status:
            raise Exception("datetime not specified.")

        result = ""
        sanitized_status = {}
        for status_item in status:
            temp = status[status_item]
            try:
                # If this is the device ID then make sure it is a UUID. Otherwise, make sure it's a number.
                if status_item == DEVICE_ID_KEY:
                    uuid.UUID(temp, version=4)
                else:
                    fractions.Fraction(temp)

                # Make sure the key isn't too long.
                if len(status_item) < 64:
                    sanitized_status[status_item] = temp
            except:
                result = "At least one value was rejected."

        self.database.create_status(sanitized_status)
        return True, result

    def handle_graph_data_request(self, values):
        """Called when a request for data associated with an attribute is received."""
        if DEVICE_ID_KEY not in values:
            raise Exception("device_id not specified.")
        if DEVICE_ATTRIBUTES_KEY not in values:
            raise Exception("attributes not specified.")
        if 'start_time' not in values:
            raise Exception("start_time not specified.")

        # Get the device ID and make sure it is a valid UUID.
        device_id = values[DEVICE_ID_KEY]
        if not InputChecker.is_uuid(device_id):
            raise Exception("Invalid device ID.")

        # Maximum number of results.
        num_results = 1000
        if 'num_results' in values:
            num_results = int(values['num_results'])

        # List of attributes whose graph data is requested.
        attributes = unquote_plus(values[DEVICE_ATTRIBUTES_KEY]).split(',')

        # Do not include results before this time.
        start_time = int(values["start_time"])

        graph_data = []

        device_status = self.database.retrieve_status(device_id, num_results)
        if device_status is None or len(device_status) == 0:
            raise Exception('Unknown device ID')

        for status in device_status:
            if DEVICE_STATUS_TIMESTAMP_KEY in status:
                datetime_num = int(status[DEVICE_STATUS_TIMESTAMP_KEY])
                if datetime_num > start_time:
                    point_data = {}
                    point_data[DEVICE_STATUS_TIMESTAMP_KEY] = datetime_num
                    for attribute in attributes:
                        # If the attribute doesn't exist for this timeslice then insert a zero
                        if attribute in status:
                            point_data[attribute] = status[attribute]
                        else:
                            point_data[attribute] = 0
                    graph_data.append(point_data)

        graph_str = "{\"points\":" + json.dumps(graph_data) + "}"
        return True, graph_str

    def handle_graph_color_request(self, values):
        """Called when a request for the graph color to use with an attribute is received."""
        if DEVICE_ID_KEY not in values:
            raise Exception("device_id not specified.")
        if DEVICE_ATTRIBUTE_KEY not in values:
            raise Exception("attribute not specified.")

        # Get the device ID and make sure it is a valid UUID.
        device_id = values[DEVICE_ID_KEY]
        if not InputChecker.is_uuid(device_id):
            raise Exception("Invalid device ID.")

        # Get the attribute name.
        attribute = unquote_plus(values[DEVICE_ATTRIBUTE_KEY])
        if not InputChecker.is_valid_decoded_str(attribute):
            raise Exception("Invalid attribute name.")

        # Retrieve the device color from the database.
        device_color = self.database.retrieve_device_color(device_id, attribute)

        # If there was nothing in the database then set it to the default of 'black'.
        if device_color is None:
            device_color = "LightGray"
        return True, device_color

    def handle_status_request(self, values):
        """Called when a request for the device status received."""
        if DEVICE_ID_KEY not in values:
            raise Exception("device_id not specified.")

        # Get the device ID and make sure it is a valid UUID.
        device_id = values[DEVICE_ID_KEY]
        if not InputChecker.is_uuid(device_id):
            raise Exception("Invalid device ID.")

        device_status = self.database.retrieve_status(device_id, 1)
        if device_status is None or len(device_status) == 0:
            raise Exception('Unknown device ID')

        first_device_status = device_status[0]
        first_device_status.pop("_id") # Leaving this in will cause all sorts of trouble
        first_device_status.pop(keys.KEY_DEVICE_ID)
        first_device_status.pop(keys.KEY_DATETIME)
        first_device_status.pop(keys.KEY_VIRTUAL_MEM_TOTAL)

        # Convert to JSON and return.
        return True, json.dumps(first_device_status)

    def handle_update_email(self, values):
        """Updates the user's email address."""
        if self.user_id is None:
            raise Exception("Not logged in.")
        if 'email' not in values:
            raise Exception("email not specified.")

        # Get the logged in user.
        current_username = self.user_mgr.get_logged_in_user()
        if current_username is None:
            raise Exception("Empty username.")

        # Decode the parameter.
        new_username = unquote_plus(values['email'])
        if not InputChecker.is_email_address(new_username):
            raise Exception("Invalid username.")

        # Get the user details.
        user_id, _, user_realname = self.database.retrieve_user(current_username)

        # Update the user's password in the database.
        if not self.user_mgr.update_user_email(user_id, new_username, user_realname):
            raise Exception("Update failed.")
        return True, ""

    def handle_update_password(self, values):
        """Updates the user's email password."""
        if self.user_id is None:
            raise Exception("Not logged in.")
        if 'old_password' not in values:
            raise Exception("Old password not specified.")
        if 'new_password1' not in values:
            raise Exception("New password not specified.")
        if 'new_password2' not in values:
            raise Exception("New password confirmation not specified.")

        # Get the logged in user.
        username = self.user_mgr.get_logged_in_user()
        if username is None:
            raise Exception("Empty username.")

        # Get the user details.
        user_id, _, user_realname = self.database.retrieve_user(username)

        # The the old and new passwords from the request.
        old_password = unquote_plus(values["old_password"])
        new_password1 = unquote_plus(values["new_password1"])
        new_password2 = unquote_plus(values["new_password2"])

        # Reauthenticate the user.
        if not self.user_mgr.authenticate_user(username, old_password):
            raise Exception("Authentication failed.")

        # Update the user's password in the database.
        if not self.user_mgr.update_user_password(user_id, username, user_realname, new_password1, new_password2):
            raise Exception("Update failed.")
        return True, ""

    def handle_delete_user(self, values):
        """Removes the user and all associated data."""
        if self.user_id is None:
            raise Exception("Not logged in.")
        if PASSWORD_KEY not in values:
            raise Exception("Password not specified.")

        # Get the logged in user.
        username = self.user_mgr.get_logged_in_user()
        if username is None:
            raise Exception("Empty username.")

        # Reauthenticate the user.
        password = unquote_plus(values['password'])
        if not self.user_mgr.authenticate_user(username, password):
            raise Exception("Authentication failed.")

        # Delete the user.
        self.user_mgr.delete_user(self.user_id)
        return True, ""

    def handle_list_devices(self, values):
        """Handles a request to list the devices registered to the current user."""
        if self.user_id is None:
            raise Exception("Not logged in.")

        # Get the user's devices.
        device_ids = self.database.retrieve_user_devices(self.user_id)

        # Add the device name.
        device_records = []
        for device_id in device_ids:
            device_record = {}
            device_record['id'] = device_id
            device_record[DEVICE_NAME_KEY] = self.database.retrieve_device_name(device_id)
            device_records.append(device_record)

        # Convert to JSON and return.
        json_result = json.dumps(device_records, ensure_ascii=False)
        return True, json_result

    def handle_set_device_name(self, values):
        """Associates a name with a device's unique identifier."""
        if self.user_id is None:
            raise Exception("Not logged in.")
        if DEVICE_ID_KEY not in values:
            raise Exception("device_id not specified.")
        if DEVICE_NAME_KEY not in values:
            raise Exception("name not specified.")

        # Get the device ID and make sure it is a valid UUID.
        device_id = values[DEVICE_ID_KEY]
        if not InputChecker.is_uuid(device_id):
            raise Exception("Invalid device ID.")

        # Make sure the user owns the device.
        device_ids = self.database.retrieve_user_devices(self.user_id)
        if device_id not in device_ids:
            raise Exception("Device not owned by the logged in user.")

        # Validate the device name.
        name = unquote_plus(values[DEVICE_NAME_KEY])
        if not InputChecker.is_valid_decoded_str(name):
            raise Exception("Invalid device name.")

        # Get the user's devices.
        devices = self.database.retrieve_user_devices(self.user_id)
        if not device_id in devices:
            raise Exception("Unknown device ID.")

        # Add the device id to the database.
        result = self.database.create_device_name(device_id, name)

        return result, ""

    def handle_set_device_attribute_color(self, values):
        """Associates a color with a device."""
        if self.user_id is None:
            raise Exception("Not logged in.")
        if DEVICE_ID_KEY not in values:
            raise Exception("device_id not specified.")

        # Get the device ID and make sure it is a valid UUID.
        device_id = values[DEVICE_ID_KEY]
        if not InputChecker.is_uuid(device_id):
            raise Exception("Invalid device ID.")

        # Make sure the user owns the device.
        device_ids = self.database.retrieve_user_devices(self.user_id)
        if device_id not in device_ids:
            raise Exception("Device not owned by the logged in user.")

        # Get the attribute name.
        attribute = unquote_plus(values['attribute'])
        if not InputChecker.is_valid_decoded_str(attribute):
            raise Exception("Invalid attribute name.")

        # Get the attribute color.
        color = unquote_plus(values['color'])
        if not InputChecker.is_valid_decoded_str(color):
            raise Exception("Invalid color.")

        # Get the user's devices.
        devices = self.database.retrieve_user_devices(self.user_id)
        if not device_id in devices:
            raise Exception("Unknown device ID.")

        # Add the device id to the database.
        result = self.database.create_device_attribute_color(device_id, attribute, color)

        return result, ""
    
    def handle_claim_device(self, values):
        """Associates a device with a user."""
        if self.user_id is None:
            raise Exception("Not logged in.")
        if DEVICE_ID_KEY not in values:
            raise Exception("device_id not specified.")

        # Get the device ID and make sure it is a valid UUID.
        device_id = values[DEVICE_ID_KEY]
        if not InputChecker.is_uuid(device_id):
            raise Exception("Invalid device ID.")

        # Make sure the device ID is real.
        device_status = self.database.retrieve_status(device_id, 1)
        if device_status is None or len(device_status) == 0:
            raise Exception('Unknown device ID')

        # Add the device id to the database.
        result = self.database.claim_device(self.user_id, device_id)

        return result, ""

    def handle_delete_device(self, values):
        """Deletes the device with the specified ID, assuming it is owned by the current user."""
        if self.user_id is None:
            raise Exception("Not logged in.")
        if DEVICE_ID_KEY not in values:
            raise Exception("device_id not specified.")

        # Get the device ID and make sure it is a valid UUID.
        device_id = values[DEVICE_ID_KEY]
        if not InputChecker.is_uuid(device_id):
            raise Exception("Invalid device ID.")

        # Make sure the user owns the device.
        device_ids = self.database.retrieve_user_devices(self.user_id)
        if device_id not in device_ids:
            raise Exception("Device not owned by the logged in user.")

        # Delete the device.
        self.database.delete_status(device_id)
        self.database.delete_device_attributes(device_id)
        self.database.unclaim_device(self.user_id, device_id)

        return True, ""

    def handle_trim(self, values):
        """Deletes device data from before the given date."""
        if self.user_id is None:
            raise Exception("Not logged in.")
        if DEVICE_ID_KEY not in values:
            raise Exception("device_id not specified.")
        if 'trim' not in values:
            raise Exception("trim date not specified.")

        # Get the device ID and make sure it is a valid UUID.
        device_id = values[DEVICE_ID_KEY]
        if not InputChecker.is_uuid(device_id):
            raise Exception("Invalid device ID.")

        # Make sure the user owns the device.
        device_ids = self.database.retrieve_user_devices(self.user_id)
        if device_id not in device_ids:
            raise Exception("Device not owned by the logged in user.")

        # Get the trim date.
        trim_date = values['trim']

        # Delete the device.
        result = self.database.delete_status_before_date(device_id, trim_date)

        return result, ""

    def handle_api_1_0_request(self, request, values):
        """Called to parse a version 1.0 API message."""
        if request is None:
            return False, ""

        if request == 'upload':
            return self.handle_create_status(values)
        elif request == 'retrieve_graph_data':
            return self.handle_graph_data_request(values)
        elif request == 'retrieve_graph_color':
            return self.handle_graph_color_request(values)
        elif request == 'retrieve_status':
            return self.handle_status_request(values)
        elif request == 'update_email':
            return self.handle_update_email(values)
        elif request == 'update_password':
            return self.handle_update_password(values)
        elif request == 'delete_user':
            return self.handle_delete_user(values)
        elif request == 'list_devices':
            return self.handle_list_devices(values)
        elif request == 'set_device_name':
            return self.handle_set_device_name(values)
        elif request == 'set_device_attribute_color':
            return self.handle_set_device_attribute_color(values)
        elif request == 'claim_device':
            return self.handle_claim_device(values)
        elif request == 'delete_device':
            return self.handle_delete_device(values)
        elif request == 'trim_data':
            return self.handle_trim(values)
        elif request == 'login':
            return self.handle_login(values)
        elif request == 'logout':
            return self.handle_logout(values)
        elif request == 'create_login':
            return self.handle_create_login(values)
        return False, ""
