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
"""Database implementation"""

import sys
import traceback
import Database

from bson.objectid import ObjectId
import pymongo

# Keys associated with session management.
SESSION_TOKEN_KEY = "cookie"
SESSION_USER_KEY = "user"
SESSION_EXPIRY_KEY = "expiry"

# Unique identifiers for a document in the database.
DATABASE_ID_KEY = "_id"

def insert_into_collection(collection, doc):
    """Handles differences in document insertion between pymongo 3 and 4."""
    if int(pymongo.__version__[0]) < 4:
        result = collection.insert(doc)
    else:
        result = collection.insert_one(doc)
    return result is not None and result.inserted_id is not None 

def update_collection(collection, doc):
    """Handles differences in document updates between pymongo 3 and 4."""
    if int(pymongo.__version__[0]) < 4:
        collection.save(doc)
        return True
    else:
        query = { DATABASE_ID_KEY: doc[DATABASE_ID_KEY] }
        new_values = { "$set" : doc }
        result = collection.update_one(query, new_values)
        return result.matched_count > 0 

class MongoDatabase(Database.Database):
    conn = None
    database = None
    status_collection = None

    def __init__(self, rootDir):
        Database.Database.__init__(self, rootDir)
        self.connect()

    def connect(self):
        """Connects/creates the database"""
        try:
            self.conn = pymongo.MongoClient('localhost:27017')
            self.database = self.conn['statusdb']
            self.users_collection = self.database['users']
            self.devices_collection = self.database['devices']
            self.status_collection = self.database['status']
            return True
        except pymongo.errors.ConnectionFailure as e:
            self.log_error("Could not connect to MongoDB: %s" % e)
        return False

    #
    # User management methods
    #

    def create_user(self, username, realname, hash):
        """Create method for a user."""
        if username is None:
            raise Exception("Unexpected empty object: username")
        if realname is None:
            raise Exception("Unexpected empty object: realname")
        if hash is None:
            raise Exception("Unexpected empty object: hash")
        if len(username) == 0:
            raise Exception("username too short")
        if len(realname) == 0:
            raise Exception("realname too short")
        if len(hash) == 0:
            raise Exception("hash too short")

        try:
            post = {"username": username, "realname": realname, "hash": hash, "devices": []}
            return insert_into_collection(self.users_collection, post)
        except:
            traceback.print_exc(file=sys.stdout)
            self.log_error(sys.exc_info()[0])
        return False

    def retrieve_user(self, username):
        """Create method for a user."""
        if username is None:
            raise Exception("Unexpected empty object: username")
        if len(username) == 0:
            raise Exception("username is empty")

        try:
            user = self.users_collection.find_one({"username": username})
            if user is not None:
                return str(user['_id']), user['hash'], user['realname']
            return None, None, None
        except:
            traceback.print_exc(file=sys.stdout)
            self.log_error(sys.exc_info()[0])
        return None, None, None

    def update_user(self, user_id, username, realname, passhash):
        """Update method for a user."""
        if user_id is None:
            raise Exception("Unexpected empty object: user_id")

        try:
            user_id_obj = ObjectId(user_id)
            values = {}
            if username is not None:
                values['username'] = username
            if realname is not None:
                values['realname'] = realname
            if passhash is not None:
                values['hash'] = passhash
            if len(values) > 0:
                self.users_collection.update_one({"_id": user_id_obj}, {"$set": values}, upsert=False)
            return True
        except:
            traceback.print_exc(file=sys.stdout)
            self.log_error(sys.exc_info()[0])
        return False

    def delete_user(self, user_id):
        """Delete method for a user."""
        if user_id is None:
            raise Exception("Unexpected empty object: user_id")

        try:
            user_id_obj = ObjectId(user_id)
            user = self.users_collection.delete_one({"_id": user_id_obj})
            if user is not None:
                return True
        except:
            traceback.print_exc(file=sys.stdout)
            self.log_error(sys.exc_info()[0])
        return False

    #
    # Device management methods
    #

    def retrieve_user_devices(self, user_id):
        """Retrieve method for a device."""
        if user_id is None:
            raise Exception("Unexpected empty object: user_id")

        try:
            user_id_obj = ObjectId(user_id)
            user = self.users_collection.find_one({"_id": user_id_obj})
            if user is not None:
                if 'devices' in user:
                    return user['devices']
        except:
            traceback.print_exc(file=sys.stdout)
            self.log_error(sys.exc_info()[0])
        return None

    def claim_device(self, user_id, device_id):
        """Associates a device with a user."""
        if user_id is None:
            raise Exception("Unexpected empty object: user_id")
        if device_id is None:
            raise Exception("Unexpected empty object: device_id")

        try:
            user_id_obj = ObjectId(user_id)
            user = self.users_collection.find_one({"_id": user_id_obj})
            if user is not None:
                device_list = []
                if 'devices' in user:
                    device_list = user['devices']
                if device_id not in device_list:
                    device_list.append(device_id)
                    user['devices'] = device_list
                    return update_collection(self.users_collection, user)
        except:
            traceback.print_exc(file=sys.stdout)
            self.log_error(sys.exc_info()[0])
        return False

    def unclaim_device(self, user_id, device_id):
        """Disassociates a device with a user."""
        if user_id is None:
            raise Exception("Unexpected empty object: user_id")
        if device_id is None:
            raise Exception("Unexpected empty object: device_id")

        try:
            user_id_obj = ObjectId(user_id)
            user = self.users_collection.find_one({"_id": user_id_obj})
            if user is not None:
                device_list = []
                if 'devices' in user:
                    device_list = user['devices']
                if device_id in device_list:
                    device_list.remove(device_id)
                    user['devices'] = device_list
                    return update_collection(self.users_collection, user)
        except:
            traceback.print_exc(file=sys.stdout)
            self.log_error(sys.exc_info()[0])
        return False
        
    def create_device_name(self, device_id, name):
        """Associates a name with a device."""
        if device_id is None:
            raise Exception("Unexpected empty object: device_id")
        if name is None:
            raise Exception("Unexpected empty object: name")

        try:
            device = self.devices_collection.find_one({"device_id": device_id})
            if device is None:
                post = {"device_id": device_id, "name": name}
                return insert_into_collection(self.devices_collection, post)

            device['name'] = name
            return update_collection(self.devices_collection, device)
        except:
            traceback.print_exc(file=sys.stdout)
            self.log_error(sys.exc_info()[0])
        return False

    def create_device_attribute_color(self, device_id, attribute, color):
        """Associates a color with a device attribute."""
        if device_id is None:
            raise Exception("Unexpected empty object: device_id")
        if attribute is None:
            raise Exception("Unexpected empty object: attribute")
        if color is None:
            raise Exception("Unexpected empty object: color")

        try:
            device = self.devices_collection.find_one({"device_id": device_id})
            if device is None:
                post = {"device_id": device_id, "colors": {attribute: color}}
                return insert_into_collection(self.devices_collection, post)

            colors = {}
            if "colors" in device:
                colors = device["colors"]
            colors[attribute] = color
            device['colors'] = colors
            return update_collection(self.devices_collection, device)
        except:
            traceback.print_exc(file=sys.stdout)
            self.log_error(sys.exc_info()[0])
        return False

    def retrieve_device_name(self, device_id):
        """Returns the name of the device with the specified device ID."""
        if device_id is None:
            raise Exception("Unexpected empty object: device_id")

        try:
            device = self.devices_collection.find_one({"device_id": device_id})
            if device is not None:
                return device['name']
        except:
            traceback.print_exc(file=sys.stdout)
            self.log_error(sys.exc_info()[0])
        return None

    def retrieve_device_color(self, device_id, attribute):
        """Returns the color associated with the specified device attribute."""
        if device_id is None:
            raise Exception("Unexpected empty object: device_id")
        if attribute is None:
            raise Exception("Unexpected empty object: attribute")

        try:
            device = self.devices_collection.find_one({"device_id": device_id})
            if device is not None:
                if "colors" in device:
                    colors = device["colors"]
                    if attribute in colors:
                        return colors[attribute]
        except:
            traceback.print_exc(file=sys.stdout)
            self.log_error(sys.exc_info()[0])
        return None

    def delete_device_attributes(self, device_id):
        """Deletes the device attributes (name, color, etc.) for the device with the specified ID."""
        if device_id is None:
            raise Exception("Unexpected empty object: device_id")

        try:
            self.devices_collection.remove({"device_id": device_id})
            return True
        except:
            traceback.print_exc(file=sys.stdout)
            self.log_error(sys.exc_info()[0])
        return False

    #
    # Status management methods
    #

    def create_status(self, status):
        if status is None:
            raise Exception("Unexpected empty object: status")

        try:
            post = {}
            for status_item in status:
                post[status_item] = status[status_item]
            return insert_into_collection(self.status_collection, post)
        except:
            traceback.print_exc(file=sys.stdout)
            self.log_error(sys.exc_info()[0])
        return False

    def retrieve_status(self, device_id, num_results):
        """Retrieves num_results statuses from the device with the specified ID."""
        if device_id is None:
            raise Exception("Unexpected empty object: device_id")

        try:
            statuses = list(self.status_collection.find({"device_id": device_id}).sort("_id", -1).skip(0).limit(num_results))
            return statuses
        except:
            traceback.print_exc(file=sys.stdout)
            self.log_error(sys.exc_info()[0])
        return None

    def delete_status(self, device_id):
        """Deletes all statuses from the device with the specified ID."""
        if device_id is None:
            raise Exception("Unexpected empty object: device_id")

        try:
            self.status_collection.remove({"device_id": device_id})
            return True
        except:
            traceback.print_exc(file=sys.stdout)
            self.log_error(sys.exc_info()[0])
        return False

    def delete_status_before_date(self, device_id, trim_date):
        """Deletes all statuses from the device with the specified ID."""
        if device_id is None:
            raise Exception("Unexpected empty object: device_id")
        if trim_date is None:
            raise Exception("Unexpected empty object: trim_date")

        try:
            self.status_collection.remove({"device_id": device_id, "datetime": { "$lt": trim_date }})
            return True
        except:
            traceback.print_exc(file=sys.stdout)
            self.log_error(sys.exc_info()[0])
        return False

    #
    # Session token management methods
    #

    def create_session_token(self, token, user, expiry):
        """Create method for a session token."""
        if token is None:
            raise Exception("Unexpected empty object: token")
        if user is None:
            raise Exception("Unexpected empty object: user")
        if expiry is None:
            raise Exception("Unexpected empty object: expiry")

        try:
            post = { SESSION_TOKEN_KEY: token, SESSION_USER_KEY: user, SESSION_EXPIRY_KEY: expiry }
            return insert_into_collection(self.sessions_collection, post)
        except:
            self.log_error(traceback.format_exc())
            self.log_error(sys.exc_info()[0])
        return False

    def retrieve_session_data(self, token):
        """Retrieve method for session data."""
        if token is None:
            raise Exception("Unexpected empty object: token")

        try:
            session_data = self.sessions_collection.find_one({ SESSION_TOKEN_KEY: token })
            if session_data is not None:
                return session_data[SESSION_USER_KEY], session_data[SESSION_EXPIRY_KEY]
        except:
            self.log_error(traceback.format_exc())
            self.log_error(sys.exc_info()[0])
        return (None, None)

    def delete_session_token(self, token):
        """Delete method for a session token."""
        if token is None:
            raise Exception("Unexpected empty object: token")

        try:
            deleted_result = self.sessions_collection.delete_one({ SESSION_TOKEN_KEY: token })
            if deleted_result is not None:
                return True
        except:
            self.log_error(traceback.format_exc())
            self.log_error(sys.exc_info()[0])
        return False
