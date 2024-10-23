#!/usr/bin/env python3

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

import argparse
import logging
import os
import platform
import pycron
import signal
import subprocess
import sys
import threading
import time
import urlparse

g_control_thread = None

def signal_handler(signal, frame):
    global g_control_thread

    logging.info("Exiting...")
    if g_control_thread:
        g_control_thread.terminate()

def shutdown():
    target = platform.system()
    if target == 'Windows':
        os.system("shutdown /s /t 1")
    elif target == 'Darwin':
        os.system("shutdown now")
    elif target == 'Linux':
        os.system('systemctl poweroff')

def restart():
    target = platform.system()
    if target == 'Windows':
        os.system("shutdown /r /t 1")
    elif target == 'Darwin':
        os.system("shutdown -r now")
    elif target == 'Linux':
        os.system("shutdown -r now")

class ControlThread(threading.Thread):
    def __init__(self, server, cron):
        threading.Thread.__init__(self)
        self.cron = cron
        self.stopped = threading.Event()
        self.interval = 60

    def terminate(self):
        logging.info("Terminating...")
        self.stopped.set()

    def check_cron_line(self, line):
        parts = line.split(' ')
        if len(parts) < 6:
            logging.error("Incorrectly formatted cron line. Expected 6 parts: " + line)
            return
        cmd = parts[5].strip()
        if len(cmd) == 0:
            logging.error("Incorrectly formatted command: " + cmd)
            return
        
        line2 = parts[0] + ' ' + parts[1] + ' ' + parts[2] + ' ' + parts[3] + ' ' + parts[4]
        if pycron.is_now(line2):
            process = subprocess.Popen([cmd], stdout=subprocess.PIPE)
            out_str, err_str = process.communicate()
            if out_str is not None and len(out_str) > 0:
                logging.info(out_str)
            if err_str is not None and len(err_str) > 0:
                logging.error(err_str)

    def check_cron(self):
        with open(self.cron) as f:
            for line in f:
                if len(line) > 0 and line[0] is not '#':
                    self.check_cron_line(line)

    def run(self):
        while not self.stopped.wait(self.interval):
            # Check the cron file to see if we need to execute any of the lines in it
            if len(self.cron) > 0:
                self.check_cron()

if __name__ == "__main__":
    signal.signal(signal.SIGINT, signal_handler)

    # Parse command line options.
    parser = argparse.ArgumentParser()
    parser.add_argument("--server", type=str, action="store", default="", help="Remote logging server (optional)", required=False)
    parser.add_argument("--cron", type=str, action="store", default="", help="cron file to use (optional)", required=False)
    parser.add_argument("--log", action="store", default="", help="Name of the log file (optional)", required=False)

    try:
        args = parser.parse_args()
    except IOError as e:
        parser.error(e)
        sys.exit(1)

    # Sanitize the server name, if applicable.
    server = args.server
    if server is not None and len(server) > 0:
        parsed_server = urlparse.urlparse(server)
        if parsed_server.scheme is '':
            server = "http://" + server

    # Check the cron file for existence, if applicable.
    if len(args.cron) > 0:
        if not os.path.isfile(args.cron):
            print("The specified cron file does not exist.")
            sys.exit(1)

    # Configure the log file, if applicable.
    if len(args.log) > 0:
        logging.basicConfig(filename=args.log,level=logging.DEBUG)

    # Start the control thread.
    g_control_thread = ControlThread(server, args.cron)
    g_control_thread.start()

    # Wait for it to finish. We do it like this so that the main thread isn't blocked and can execute the signal handler.
    if sys.version_info[0] < 3:
        alive_func = g_control_thread.isAlive
    else:
        alive_func = g_control_thread.is_alive
    while alive_func():
        time.sleep(1)
    g_control_thread.join()
