# -*- coding: utf-8 -*-
# 
# # MIT License
# 
# Copyright (c) 2017 Michael J Simms
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
import pymongo

def insert_into_collection(collection, doc):
    """Handles differences in document insertion between pymongo 3 and 4."""
    if int(pymongo.__version__[0]) < 4:
        result = collection.insert(doc)
    else:
        result = collection.insert_one(doc)
    return result is not None and result.inserted_id is not None 

class DatabaseException(Exception):
    """Exception thrown by the database."""

    def __init__(self, *args):
        Exception.__init__(self, args)

    def __init__(self, message):
        self.message = message
        Exception.__init__(self, message)

class MongoDatabase(object):
    """Mongo DB implementation of the application database."""
    conn = None
    database = None
    status_collection = None

    def __init__(self):
        super(MongoDatabase, self).__init__()

    def connect(self, database_url):
        """Connects/creates the database"""
        try:
            # If we weren't given a database URL then assume localhost and default port.
            self.conn = pymongo.MongoClient('mongodb://' + database_url + '/?uuidRepresentation=pythonLegacy')

            # Database.
            self.database = self.conn['statusdb']
            if self.database is None:
                raise DatabaseException.DatabaseException("Could not connect to MongoDB.")

            # Handles to the various collections.
            self.users_collection = self.database['status']
        except pymongo.errors.ConnectionFailure as e:
            raise DatabaseException.DatabaseException("Could not connect to MongoDB: %s" % e)

    def create_status(self, values):
        """Create method for a status record."""
        if values is None:
            raise Exception("Unexpected empty object: values")

        try:
            return insert_into_collection(self.users_collection, values)
        except:
            self.log_error(traceback.format_exc())
            self.log_error(sys.exc_info()[0])
        return False
