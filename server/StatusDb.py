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

from bson.objectid import ObjectId

import os
import pymongo
import sys
import traceback
import Database

class MongoDatabase(Database.Database):
    conn = None
    db = None
    status_collection = None

    def __init__(self, rootDir):
        Database.Database.__init__(self, rootDir)
        self.create()

    def create(self):
        try:
            self.conn = pymongo.MongoClient('localhost:27017')
            self.db = self.conn['statusdb']
            self.status_collection = self.db['status']
            return True
        except pymongo.errors.ConnectionFailure, e:
            self.log_error("Could not connect to MongoDB: %s" % e)
        return False

    def create_status(self, status):
        if status is None:
            self.log_error(MongoDatabase.create_status.__name__ + "Unexpected empty object: status")
            return False

        try:
            post = {}
            self.status_collection.insert(post)
            return True
        except:
            traceback.print_exc(file=sys.stdout)
            self.log_error(sys.exc_info()[0])
        return False

    def retrieve_status(self, device):
        if device is None:
            self.log_error(MongoDatabase.retrieve_user.__name__ + "Unexpected empty object: device")
            return None

        try:
            statuses = self.status_collection.find_one({"device": device})
            if statuses is not None:
                pass
            return None
        except:
            traceback.print_exc(file=sys.stdout)
            self.log_error(sys.exc_info()[0])
        return None
