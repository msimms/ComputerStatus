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

import inspect
import logging
import mako
import markdown
import os
import sys
import Api
import InputChecker
import StatusDb

from mako.lookup import TemplateLookup
from mako.template import Template

currentdir = os.path.dirname(os.path.abspath(inspect.getfile(inspect.currentframe())))
parentdir = os.path.dirname(currentdir)
clientdir = os.path.join(parentdir, 'client')
sys.path.insert(0, clientdir)
import keys

LOGIN_URL = '/login'
DASHBOARD_URL = '/dashboard'
HTML_DIR = 'html'


class RedirectException(Exception):
    """This is thrown when the app needs to redirect to another page."""

    def __init__(self, url):
        self.url = url
        super(RedirectException, self).__init__()


class App(object):
    """Class containing the URL handlers."""

    def __init__(self, user_mgr, root_dir, root_url):
        self.user_mgr = user_mgr
        self.root_dir = root_dir
        self.root_url = root_url
        self.tempfile_dir = os.path.join(self.root_dir, 'tempfile')
        self.tempmod_dir = os.path.join(self.root_dir, 'tempmod')
        self.database = StatusDb.MongoDatabase(root_dir)

        self.tempfile_dir = os.path.join(root_dir, 'tempfile')
        if not os.path.exists(self.tempfile_dir):
            os.makedirs(self.tempfile_dir)

    def terminate(self):
        """Destructor"""
        logging.info("Terminating...")
        self.user_mgr.terminate()
        self.user_mgr = None

    def log_error(self, log_str):
        """Writes an error message to the log file."""
        logger = logging.getLogger()
        logger.error(log_str)

    def error(self, error_str=None):
        """Renders the error page."""
        try:
            error_html_file = os.path.join(self.root_dir, HTML_DIR, 'error.html')
            my_template = Template(filename=error_html_file, module_directory=self.tempmod_dir)
            if error_str is None:
                error_str = "Internal Error."
            return my_template.render(error=error_str)
        except:
            pass
        return ""

    def create_navbar(self, logged_in=True):
        """Helper function for building the navigation bar."""
        navbar_str = "<nav>\n\t<ul>\n"
        navbar_str += "\t\t<li><a href=\"https://github.com/msimms/ComputerStatus/\">GitHub</a></li>\n"
        if logged_in is True:
            navbar_str += "\t\t<li><a href=\"" + self.root_url + "/dashboard/\">Dashboard</a></li>\n"
            navbar_str += "\t\t<li><a href=\"" + self.root_url + "/settings/\">Settings</a></li>\n"
            navbar_str += "\t\t<li><a href=\"" + self.root_url + "/logout/\">Log Out</a></li>\n"
        navbar_str += "\t</ul>\n</nav>"
        return navbar_str

    def device(self, device_id):
        """Page for displaying graphs about a particular device."""

        title_str = self.database.retrieve_device_name(device_id)
        if title_str is None:
            title_str = "Device ID: " + str(device_id)

        table_str = "\t<table>\n"
        degree_sign = u'\N{DEGREE SIGN}'

        keys_to_graph = []
        statuses = self.database.retrieve_status(device_id, 1)
        if statuses is not None and len(statuses) > 0:
            last_status = statuses[len(statuses) - 1]

            # Latest CPU values.
            if keys.KEY_CPU_PERCENT in last_status:
                table_str += "\t\t<td>Current CPU Utilization</td><td>" + str(last_status[keys.KEY_CPU_PERCENT]) + "%</td><tr>\n"
                keys_to_graph.append(keys.KEY_CPU_PERCENT)
            if keys.KEY_CPU_TEMPERATURE in last_status:
                table_str += "\t\t<td>Current CPU Temperature</td><td>" + str(last_status[keys.KEY_CPU_TEMPERATURE]) + degree_sign + "C</td><tr>\n"
                keys_to_graph.append(keys.KEY_CPU_TEMPERATURE)

            # Latest memory value.
            if keys.KEY_VIRTUAL_MEM_PERCENT in last_status:
                table_str += "\t\t<td>Current RAM Utilization</td><td>" + str(last_status[keys.KEY_VIRTUAL_MEM_PERCENT]) + "%</td><tr>\n"
                keys_to_graph.append(keys.KEY_VIRTUAL_MEM_PERCENT)

            # Latest GPU value (single GPU).
            if keys.KEY_GPU_PERCENT in last_status:
                table_str += "\t\t<td>Current GPU Utilization</td><td>" + str(last_status[keys.KEY_GPU_PERCENT]) + "%</td><tr>\n"
                keys_to_graph.append(keys.KEY_GPU_PERCENT)
            if keys.KEY_GPU_TEMPERATURE in last_status:
                table_str += "\t\t<td>Current GPU Temperature</td><td>" + str(last_status[keys.KEY_GPU_TEMPERATURE]) + degree_sign + "C</td><tr>\n"
                keys_to_graph.append(keys.KEY_GPU_TEMPERATURE)

            # Latest GPU values (multiple GPUs).
            found_gpu = True
            while found_gpu:
                gpu_index = 1

                # Utilization.
                gpu_key_name = keys.KEY_GPUX_PERCENT.replace('X', str(gpu_index))
                found_gpu = gpu_key_name in last_status
                if found_gpu:
                    table_str += "\t\t<td>Current GPU " + str(gpu_index) + " Utilization</td><td>" + str(last_status[keys.KEY_GPU_TEMPERATURE]) + "%</td><tr>\n"
                    keys_to_graph.append(gpu_key_name)
                
                # Temperature.
                gpu_key_name = keys.KEY_GPUX_TEMPERATURE.replace('X', str(gpu_index))
                found_gpu = gpu_key_name in last_status
                if found_gpu:
                    table_str += "\t\t<td>Current GPU " + str(gpu_index) + " Temperature</td><td>" + str(last_status[keys.KEY_GPU_TEMPERATURE]) + degree_sign + "C</td><tr>\n"
                    keys_to_graph.append(gpu_key_name)

            # Latest network values.            
            if keys.KEY_NETWORK_BYTES_SENT in last_status:
                table_str += "\t\t<td>Bytes Sent</td><td>" + str(last_status[keys.KEY_NETWORK_BYTES_SENT]) + " Bytes </td><tr>\n"
                keys_to_graph.append(keys.KEY_NETWORK_BYTES_SENT)
            if keys.KEY_NETWORK_BYTES_RECEIVED in last_status:
                table_str += "\t\t<td>Bytes Received</td><td>" + str(last_status[keys.KEY_NETWORK_BYTES_RECEIVED]) + " Bytes </td><tr>\n"
                keys_to_graph.append(keys.KEY_NETWORK_BYTES_RECEIVED)

        table_str += "\t</table>\n"
        keys_to_graph = str(keys_to_graph).replace('\', \'', ',')
        keys_to_graph = keys_to_graph.replace('[', '')
        keys_to_graph = keys_to_graph.replace(']', '')

        device_html_file = os.path.join(self.root_dir, HTML_DIR, 'device.html')
        my_template = Template(filename=device_html_file, module_directory=self.tempmod_dir)
        return my_template.render(nav=self.create_navbar(), root_url=self.root_url, title=title_str, device_id=device_id, table=table_str, keys_to_graph=keys_to_graph)

    def claim_device(self, device_id):
        """Associates a device with a user."""

        # Get the logged in user.
        username = self.user_mgr.get_logged_in_user()
        if username is None:
            raise RedirectException(LOGIN_URL)

        # Get the details of the logged in user.
        user_id, _, _ = self.user_mgr.retrieve_user(username)
        if user_id is None:
            self.log_error('Unknown user ID')
            raise RedirectException(LOGIN_URL)

        # Make sure the device ID is real.
        device_status = self.database.retrieve_status(device_id, 1)
        if device_status is None or len(device_status) == 0:
            self.log_error('Unknown device ID')
            raise RedirectException(DASHBOARD_URL)

        # Add the device id to the database.
        self.database.claim_device(user_id, device_id)

        # Refresh the dashboard page.
        raise RedirectException(DASHBOARD_URL)

    def delete_device(self, device_id):
        """Deletes the device with the specified ID, assuming it is owned by the current user."""

        # Get the logged in user.
        username = self.user_mgr.get_logged_in_user()
        if username is None:
            raise RedirectException(LOGIN_URL)

        # Get the details of the logged in user.
        user_id, _, _ = self.user_mgr.retrieve_user(username)
        if user_id is None:
            self.log_error('Unknown user ID')
            raise RedirectException(LOGIN_URL)

        # Get the user's devices.
        devices = self.database.retrieve_user_devices(user_id)
        if not device_id in devices:
            self.log_error('Unknown device ID')
            raise RedirectException(DASHBOARD_URL)

        # Delete the device.
        self.database.delete_status(device_id)
        self.database.delete_device_attributes(device_id)
        self.database.unclaim_device(user_id, device_id)

        # Refresh the dashboard page.
        raise RedirectException(DASHBOARD_URL)

    def set_device_name(self, device_id, name):
        """Associates a name with a device's unique identifier."""

        # Get the logged in user.
        username = self.user_mgr.get_logged_in_user()
        if username is None:
            raise RedirectException(LOGIN_URL)

        # Get the details of the logged in user.
        user_id, _, _ = self.user_mgr.retrieve_user(username)
        if user_id is None:
            self.log_error('Unknown user ID')
            raise RedirectException(LOGIN_URL)

        # Validate the device name.
        if not InputChecker.is_valid(name):
            self.log_error('Invalid device name')
            raise RedirectException(DASHBOARD_URL)

        # Get the user's devices.
        devices = self.database.retrieve_user_devices(user_id)
        if not device_id in devices:
            self.log_error('Unknown device ID')
            raise RedirectException(DASHBOARD_URL)

        # Add the device id to the database.
        self.database.create_device_name(device_id, name)

        # Refresh the dashboard page.
        raise RedirectException(DASHBOARD_URL)

    def set_device_attribute_color(self, device_id, attribute, color):
        """Associates a color with a device."""

        # Get the logged in user.
        username = self.user_mgr.get_logged_in_user()
        if username is None:
            raise RedirectException(LOGIN_URL)

        # Get the details of the logged in user.
        user_id, _, _ = self.user_mgr.retrieve_user(username)
        if user_id is None:
            self.log_error('Unknown user ID')
            raise RedirectException(LOGIN_URL)

        # Get the user's devices.
        devices = self.database.retrieve_user_devices(user_id)
        if not device_id in devices:
            self.log_error('Unknown device ID')
            raise RedirectException(DASHBOARD_URL)

        # Add the device id to the database.
        self.database.create_device_attribute_color(device_id, attribute, color)

        # Refresh the dashboard page.
        raise RedirectException(DASHBOARD_URL)

    def dashboard(self, *args, **kw):
        """Page for displaying the devices owned by a particular user."""

        # Get the logged in user.
        username = self.user_mgr.get_logged_in_user()
        if username is None:
            raise RedirectException(LOGIN_URL)

        # Get the details of the logged in user.
        user_id, _, _ = self.user_mgr.retrieve_user(username)
        if user_id is None:
            self.log_error('Unknown user ID')
            raise RedirectException(LOGIN_URL)

        # Get the user's devices.
        devices = self.database.retrieve_user_devices(user_id)

        # Render a table containing the user's devices.
        device_table_str = "\t<table>\n"
        device_table_str += "\t\t<td><b>Name</b></td><td><b>Device ID</b></td><td></td><tr>\n"
        if devices is not None:
            for device in devices:
                device_id_str = str(device)
                device_name = self.database.retrieve_device_name(device_id_str)
                if device_name is None:
                    device_name = "Untitled"
                device_table_str += "\t\t<td>" + device_name + "</td><td><a href=\"" + self.root_url + "/device/" + device_id_str + "\">" + device_id_str + "</a></td><td><button type=\"button\" onclick=\"return on_delete('" + device_id_str + "')\">Delete</button></td><tr>\n"
        device_table_str += "\t</table>\n"

        # Render the dashboard page.
        dashboard_html_file = os.path.join(self.root_dir, HTML_DIR, 'dashboard.html')
        my_template = Template(filename=dashboard_html_file, module_directory=self.tempmod_dir)
        return my_template.render(nav=self.create_navbar(), root_url=self.root_url, devices=device_table_str)

    def settings(self, *args, **kw):
        """Renders the user's settings page."""

        # Get the logged in user.
        username = self.user_mgr.get_logged_in_user()
        if username is None:
            raise RedirectException(LOGIN_URL)

        # Get the details of the logged in user.
        user_id, _, user_realname = self.user_mgr.retrieve_user(username)
        if user_id is None:
            self.log_error('Unknown user ID')
            raise RedirectException(LOGIN_URL)

        # Render from template.
        html_file = os.path.join(self.root_dir, HTML_DIR, 'settings.html')
        my_template = Template(filename=html_file, module_directory=self.tempmod_dir)
        return my_template.render(nav=self.create_navbar(), root_url=self.root_url, email=username, name=user_realname)

    def submit_login(self, email, password):
        """Processes a login."""

        if email is None or password is None:
            raise Exception("An email address and password were not provided.")
        else:
            if self.user_mgr.authenticate_user(email, password):
                self.user_mgr.create_new_session(email)
                raise RedirectException(DASHBOARD_URL)
            else:
                raise Exception("Unknown error.")

    def submit_new_login(self, email, realname, password1, password2, *args, **kw):
        """Creates a new login."""

        if self.user_mgr.create_user(email, realname, password1, password2):
            self.user_mgr.create_new_session(email)
            raise RedirectException(DASHBOARD_URL)
        else:
            raise Exception("Unknown error.")

    def login(self):
        """Renders the login page."""

        # If a user is already logged in then go straight to the landing page.
        username = self.user_mgr.get_logged_in_user()
        if username is not None:
            raise RedirectException(DASHBOARD_URL)

        html = ""
        readme_file_name = os.path.realpath(os.path.join(self.root_dir, '..', 'README.md'))
        with open(readme_file_name, 'r') as readme_file:
            md = readme_file.read()
            extensions = ['extra', 'smarty']
            html = markdown.markdown(md, extensions=extensions, output_format='html5')

        login_html_file = os.path.join(self.root_dir, HTML_DIR, 'login.html')
        my_template = Template(filename=login_html_file, module_directory=self.tempmod_dir)
        return my_template.render(nav=self.create_navbar(False), root_url=self.root_url, readme=html)

    def create_login(self):
        """Renders the create login page."""
        create_login_html_file = os.path.join(self.root_dir, HTML_DIR, 'create_login.html')
        my_template = Template(filename=create_login_html_file, module_directory=self.tempmod_dir)
        return my_template.render(nav=self.create_navbar(False), root_url=self.root_url)

    def logout(self):
        """Ends the logged in session."""

        # Get the logged in user.
        username = self.user_mgr.get_logged_in_user()
        if username is None:
            raise RedirectException(LOGIN_URL)

        # Clear the session.
        self.user_mgr.clear_session()

        # Send the user back to the login screen.
        raise RedirectException(LOGIN_URL)

    def api(self, user_id, method, params):
        """Processes API requests."""
        api = Api.Api(self.root_dir, self.user_mgr, user_id)
        handled, response = api.handle_api_1_0_request(method, params)
        return handled, response
