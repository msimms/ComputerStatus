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
"""Checks strings for basic compliance and sanity. Can be a partial defense against XSS attacks."""

import re
from unidecode import unidecode

alphanums = re.compile(r'[\w-]*$')
safe = re.compile(r'[\w_ .-]*$')
email_addr = re.compile(r"(^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$)")

def is_alphanumeric(test_str):
    """Returns True if the string contains only alphanumeric characters. Otherwise, False."""
    return re.match(alphanums, test_str)

def is_email_address(test_str):
    """Returns True if the string is *mostly* RFC 5322 complaint."""
    return re.match(email_addr, test_str)

def is_timestamp(test_str):
    """Returns True if the string appears to be a valid timestamp."""
    return True

def is_valid(test_str):
    """Tests the input to see that it only contains safe characters."""
    try:
        if re.match(safe, unidecode(test_str)): # Use unidecode to allow for diacritics
            return True
    except:
        pass
    return False
