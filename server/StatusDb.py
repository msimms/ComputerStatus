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

class MongoDatabase(Database.Database):
    conn = None
    database = None
    status_collection = None

    def __init__(self, rootDir):
        Database.Database.__init__(self, rootDir)
        self.create()

    def create(self):
        """Connects/creates the database"""
        try:
            self.conn = pymongo.MongoClient('localhost:27017')
            self.database = self.conn['statusdb']
            self.users_collection = self.database['users']
            self.devices_collection = self.database['devices']
            self.status_collection = self.database['status']
            return True
        except pymongo.errors.ConnectionFailure, e:
            self.log_error("Could not connect to MongoDB: %s" % e)
        return False

    def create_user(self, username, realname, hash):
        """Create method for a user."""
        if username is None:
            self.log_error(MongoDatabase.create_user.__name__ + "Unexpected empty object: username")
            return False
        if realname is None:
            self.log_error(MongoDatabase.create_user.__name__ + "Unexpected empty object: realname")
            return False
        if hash is None:
            self.log_error(MongoDatabase.create_user.__name__ + "Unexpected empty object: hash")
            return False
        if len(username) == 0:
            self.log_error(MongoDatabase.create_user.__name__ + "username too short")
            return False
        if len(realname) == 0:
            self.log_error(MongoDatabase.create_user.__name__ + "realname too short")
            return False
        if len(hash) == 0:
            self.log_error(MongoDatabase.create_user.__name__ + "hash too short")
            return False

        try:
            post = {"username": username, "realname": realname, "hash": hash, "devices": []}
            self.users_collection.insert(post)
            return True
        except:
            traceback.print_exc(file=sys.stdout)
            self.log_error(sys.exc_info()[0])
        return False

    def retrieve_user(self, username):
        """Create method for a user."""
        if username is None:
            self.log_error(MongoDatabase.retrieve_user.__name__ + "Unexpected empty object: username")
            return None, None, None
        if len(username) == 0:
            self.log_error(MongoDatabase.retrieve_user.__name__ + "username is empty")
            return None, None, None

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
            self.log_error(MongoDatabase.update_user.__name__ + "Unexpected empty object: user_id")
            return False

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
            self.log_error(MongoDatabase.delete_user.__name__ + "Unexpected empty object: user_id")
            return False

        try:
            user_id_obj = ObjectId(user_id)
            user = self.users_collection.delete_one({"_id": user_id_obj})
            if user is not None:
                return True
        except:
            traceback.print_exc(file=sys.stdout)
            self.log_error(sys.exc_info()[0])
        return False

    def retrieve_user_devices(self, user_id):
        """Retrieve method for a device."""
        if user_id is None:
            self.log_error(MongoDatabase.retrieve_user_devices.__name__ + "Unexpected empty object: user_id")
            return None

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
            self.log_error(MongoDatabase.claim_device.__name__ + "Unexpected empty object: user_id")
            return False
        if device_id is None:
            self.log_error(MongoDatabase.claim_device.__name__ + "Unexpected empty object: device_id")
            return False

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
                    self.users_collection.save(user)
            return True
        except:
            traceback.print_exc(file=sys.stdout)
            self.log_error(sys.exc_info()[0])
        return False

    def unclaim_device(self, user_id, device_id):
        """Disassociates a device with a user."""
        if user_id is None:
            self.log_error(MongoDatabase.unclaim_device.__name__ + "Unexpected empty object: user_id")
            return False
        if device_id is None:
            self.log_error(MongoDatabase.unclaim_device.__name__ + "Unexpected empty object: device_id")
            return False

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
                    self.users_collection.save(user)
            return True
        except:
            traceback.print_exc(file=sys.stdout)
            self.log_error(sys.exc_info()[0])
        return False
        
    def create_device_name(self, device_id, name):
        """Associates a name with a device."""
        if device_id is None:
            self.log_error(MongoDatabase.create_device_name.__name__ + "Unexpected empty object: device_id")
            return None
        if name is None:
            self.log_error(MongoDatabase.create_device_name.__name__ + "Unexpected empty object: name")
            return None

        try:
            device = self.devices_collection.find_one({"device_id": device_id})
            if device is None:
                post = {"device_id": device_id, "name": name}
                self.devices_collection.insert(post)
            else:
                device['name'] = name
                self.devices_collection.save(device)
            return True
        except:
            traceback.print_exc(file=sys.stdout)
            self.log_error(sys.exc_info()[0])
        return None

    def create_device_attribute_color(self, device_id, attribute, color):
        """Associates a color with a device attribute."""
        if device_id is None:
            self.log_error(MongoDatabase.create_device_attribute_color.__name__ + "Unexpected empty object: device_id")
            return None
        if attribute is None:
            self.log_error(MongoDatabase.create_device_attribute_color.__name__ + "Unexpected empty object: attribute")
            return None
        if color is None:
            self.log_error(MongoDatabase.create_device_attribute_color.__name__ + "Unexpected empty object: color")
            return None

        try:
            device = self.devices_collection.find_one({"device_id": device_id})
            if device is None:
                post = {"device_id": device_id, "colors": {attribute: color}}
                self.devices_collection.insert(post)
            else:
                colors = {}
                if "colors" in device:
                    colors = device["colors"]
                colors[attribute] = color
                device['colors'] = colors
                self.devices_collection.save(device)
            return True
        except:
            traceback.print_exc(file=sys.stdout)
            self.log_error(sys.exc_info()[0])
        return None

    def retrieve_device_name(self, device_id):
        """Returns the name of the device with the specified device ID."""
        if device_id is None:
            self.log_error(MongoDatabase.retrieve_device_name.__name__ + "Unexpected empty object: device_id")
            return None

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
            self.log_error(MongoDatabase.retrieve_device_color.__name__ + "Unexpected empty object: device_id")
            return None
        if attribute is None:
            self.log_error(MongoDatabase.retrieve_device_color.__name__ + "Unexpected empty object: attribute")
            return None

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
            self.log_error(MongoDatabase.delete_device_attributes.__name__ + "Unexpected empty object: device_id")
            return False

        try:
            self.devices_collection.remove({"device_id": device_id})
            return True
        except:
            traceback.print_exc(file=sys.stdout)
            self.log_error(sys.exc_info()[0])
        return False

    def create_status(self, status):
        if status is None:
            self.log_error(MongoDatabase.create_status.__name__ + "Unexpected empty object: status")
            return False

        try:
            post = {}
            for status_item in status:
                post[status_item] = status[status_item]
            self.status_collection.insert(post)
            return True
        except:
            traceback.print_exc(file=sys.stdout)
            self.log_error(sys.exc_info()[0])
        return False

    def retrieve_status(self, device_id, num_results):
        """Retrieves num_results statuses from the device with the specified ID."""
        if device_id is None:
            self.log_error(MongoDatabase.retrieve_status.__name__ + "Unexpected empty object: device_id")
            return None

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
            self.log_error(MongoDatabase.delete_status.__name__ + "Unexpected empty object: device_id")
            return False

        try:
            self.status_collection.remove({"device_id": device_id})
            return True
        except:
            traceback.print_exc(file=sys.stdout)
            self.log_error(sys.exc_info()[0])
        return False
