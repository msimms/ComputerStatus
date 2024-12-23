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
"""Implements client monitoring and (optional) reporting to the server."""

import argparse
import logging
import mongodb
import os
import platform
import re
import signal
import subprocess
import sys
import threading
import time
if sys.version_info[0] < 3:
    import imp
    import urlparse
else:
    from importlib.machinery import SourceFileLoader
    import urllib.parse as urlparse
import uuid
import requests
import psutil
import cpu_status
import keys

g_monitor_thread = None

def signal_handler(signal, frame):
    global g_monitor_thread

    logging.info("Exiting...")
    if g_monitor_thread:
        g_monitor_thread.terminate()

class MonitorThread(threading.Thread):
    def __init__(self, interval, server_url, mongo_url, id_file, post_file, verbose, do_cpu_check, do_mem_check, do_net_check, ping_host, do_gpu_check):
        threading.Thread.__init__(self)
        self.stopped = threading.Event()
        self.interval = interval
        self.server_url = server_url
        self.mongo_url = mongo_url
        self.post_file = post_file
        self.verbose = verbose
        self.do_cpu_check = do_cpu_check
        self.do_mem_check = do_mem_check
        self.do_net_check = do_net_check
        self.ping_host = ping_host
        self.do_gpu_check = do_gpu_check
        self.last_net_io = None
        self.post_module = None
        if os.path.isfile(self.post_file):
            if sys.version_info[0] < 3:
                self.post_module = imp.load_source("", self.post_file)
            else:
                self.post_module = mymodule = SourceFileLoader('modname', self.post_file).load_module()

        if self.server_url or self.mongo_url:
            # Look for device ID file; generate one if not found.
            self.device_id = None
            if os.path.isfile(id_file):
                with open(id_file, 'r') as device_id_file:
                    self.device_id = device_id_file.read()
            if self.device_id is None:
                self.device_id = str(uuid.uuid4())
                with open(id_file, 'w') as device_id_file:
                    device_id_file.write(self.device_id)

    def terminate(self):
        """Destructor"""
        logging.info("Terminating...")
        self.stopped.set()

    def send_to_server(self, values):
        """Sends the values to the server for archival."""
        try:
            url = self.server_url + "/api/1.0/upload"
            r = requests.post(url, data=values)
            logging.info("Server Response: " + str(r))
            if self.verbose:
                print(r)
        except:
            logging.error("Error sending to the server.")

    def send_to_mongo(self, values):
        """Sends the values to a mongodb instance for archival."""
        try:
            db = mongodb.MongoDatabase()
            db.connect(self.mongo_url)
            db.create_status(values)
        except:
            logging.error("Error sending to mongodb.")    

    def check_gpu(self, values):
        """Appends GPU values to the 'values' dictionary."""
        try:
            process = subprocess.Popen(['nvidia-smi', '--query-gpu=name,pci.bus_id,driver_version,pstate,pcie.link.gen.max,pcie.link.gen.current,temperature.gpu,utilization.gpu,utilization.memory,memory.total,memory.free,memory.used', '--format=csv'], stdout=subprocess.PIPE)
            out_str, _ = process.communicate()
            gpu_strs = out_str.split('\n')

            # Get rid of the column headers.
            if len(gpu_strs) > 0:
                gpu_strs = gpu_strs[1:]

            # Process each GPU string.
            multi_gpu = len(gpu_strs) > 1
            gpu_index = 1
            for gpu_str in gpu_strs:
                out = gpu_str.split(',')
                if len(out) > 1:
                    if multi_gpu:
                        values[keys.KEY_GPUX_NAME.replace('X', str(gpu_index))] = out[0].strip(' \t\n\r')
                        values[keys.KEY_GPUX_TEMPERATURE.replace('X', str(gpu_index))] = int(out[6].strip(' \t\n\r'))
                        values[keys.KEY_GPUX_PERCENT.replace('X', str(gpu_index))] = int(out[7].strip(' \t\n\r%%s'))
                        gpu_index = gpu_index + 1
                    else:
                        values[keys.KEY_GPU_NAME] = out[0].strip(' \t\n\r')
                        values[keys.KEY_GPU_TEMPERATURE] = int(out[6].strip(' \t\n\r'))
                        values[keys.KEY_GPU_PERCENT] = int(out[7].strip(' \t\n\r%%s'))
        except:
            logging.error("Error collecting GPU stats.")

    def check_cpu(self, values):
        """Appends current CPU values to the 'values' dictionary."""
        try:
            cpu_percent = psutil.cpu_percent()
            values[keys.KEY_CPU_PERCENT] = cpu_percent
            cpu_times = psutil.cpu_times()
            values[keys.KEY_CPU_USER_TIMES] = cpu_times.user
        except:
            logging.error("Error collecting CPU stats.")

        try:
            cpu_temp = cpu_status.cpu_temperature()
            if cpu_temp > 0:
                values['cpu - temperature'] = cpu_temp
        except:
            pass

    def check_mem(self, values):
        """Appends current memory values to the 'values' dictionary."""
        try:
            virt_mem = psutil.virtual_memory()
            values[keys.KEY_VIRTUAL_MEM_TOTAL] = virt_mem.total
            values[keys.KEY_VIRTUAL_MEM_PERCENT] = virt_mem.percent
        except:
            logging.error("Error collecting memory stats.")

    def check_net(self, values):
        """Appends current network stats to the 'values' dictionary."""
        try:
            net_io = psutil.net_io_counters()
            values[keys.KEY_NETWORK_BYTES_SENT] = net_io.bytes_sent
            values[keys.KEY_NETWORK_BYTES_RECEIVED] = net_io.bytes_recv
            if self.last_net_io is not None:
                values[keys.KEY_NETWORK_BYTES_SENT_PER_SAMPLE] = net_io.bytes_sent - self.last_net_io.bytes_sent
                values[keys.KEY_NETWORK_BYTES_RECEIVED_PER_SAMPLE] = net_io.bytes_recv - self.last_net_io.bytes_recv
            self.last_net_io = net_io
        except:
            logging.error("Error collecting network stats.")

    def check_ping(self, values, hostname):
        """Runs a ping test and appends the result to the 'values' dictionary."""
        try:
            # Different count flags for Windows vs everyone else.
            target = platform.system()
            if target == 'Windows':
                flag = "-n"
            else:
                flag = "-c"

            # Run the command.
            p = subprocess.Popen(["ping", flag, "1", hostname], stdout=subprocess.PIPE)
            response = p.stdout.read()

            # Find the part of the response text that has the time (different for Windows).
            if target == 'Windows':
                end_str = "ms"
            else:
                end_str = " ms"
            match = re.search("time=.*" + end_str, str(response))

            # If we have a match then extract the timestamp.
            if match:
                match = match.group()
                submatch = match[5:match.find(end_str)]
                values[keys.KEY_PING_TIME_MS] = float(submatch)
        except:
            logging.error("Error performing ping test.")

    def execute_post_file(self, values):
        """Executes the post process file. This is where the user can specify logic to run after each check."""
        try:
            if self.post_module is not None:
                self.post_module.do(values)
        except:
            logging.error("Error executing the post processing code.")

    def run(self):
        """Main run loop."""
        while not self.stopped.wait(self.interval):
            values = {}

            # Do the checks.
            if self.do_cpu_check:
                self.check_cpu(values)
            if self.do_mem_check:
                self.check_mem(values)
            if self.do_net_check:
                self.check_net(values)
            if len(self.ping_host) > 0:
                self.check_ping(values, self.ping_host)
            if self.do_gpu_check:
                self.check_gpu(values)

            # Append the device id and timestamp.
            values[keys.KEY_DEVICE_ID] = self.device_id
            values[keys.KEY_DATETIME] = int(time.time())

            # Post the results.
            if self.server_url:
                self.send_to_server(values)
            if self.mongo_url:
                self.send_to_mongo(values)

            # Logging.
            logging.info(values)
            if self.verbose:
                print(values)

            # Do any post-check actions.
            if self.post_file is not None and len(self.post_file) > 0:
                self.execute_post_file(values)

def main():
    """Entry point"""
    global g_monitor_thread

    # Parse command line options.
    parser = argparse.ArgumentParser()
    parser.add_argument("--interval", type=int, default=60, help="Frequency (in seconds) at which to sample.", required=False)
    parser.add_argument("--server", type=str, action="store", default="", help="Remote logging server (optional)", required=False)
    parser.add_argument("--mongo_url", type=str, action="store", default="", help="Mongo DB URL (optional)", required=False)
    parser.add_argument("--id_file", type=str, action="store", default="device_id.txt", help="Name of the file containing the device's unique identifier (optional)", required=False)
    parser.add_argument("--post", type=str, action="store", default="", help="Post processing code module (optional)", required=False)
    parser.add_argument("--verbose", action="store_true", default=True, help="TRUE to enable verbose mode", required=False)
    parser.add_argument("--log", action="store", default="", help="Name of the log file (optional)", required=False)
    parser.add_argument("--cpu", action="store_true", default=True, help="TRUE if sampling the CPU", required=False)
    parser.add_argument("--net", action="store_true", default=True, help="TRUE if sampling network I/O", required=False)
    parser.add_argument("--mem", action="store_true", default=True, help="TRUE if sampling memory", required=False)
    parser.add_argument("--ping", type=str, action="store", default="", help="Supply the hostname if sampling ping times (ex: --ping 1.1.1.1)", required=False)
    parser.add_argument("--gpu", action="store_true", default=False, help="TRUE if sampling the GPU (Nvidia only)", required=False)

    try:
        args = parser.parse_args()
    except IOError as e:
        parser.error(e)
        sys.exit(1)

    # Sanitize the server name, if applicable.
    server = args.server
    if server is not None and len(server) > 0:
        parsed_server = urlparse.urlparse(server)
        if parsed_server.scheme == '':
            server = "http://" + server

    # Configure the log file, if applicable.
    if len(args.log) > 0:
        logging.basicConfig(filename=args.log,level=logging.DEBUG)

    # Start the monitor thread.
    g_monitor_thread = MonitorThread(args.interval, server, args.mongo_url, args.id_file, args.post, args.verbose, args.cpu, args.mem, args.net, args.ping, args.gpu)
    g_monitor_thread.start()

    # Wait for it to finish. We do it like this so that the main thread isn't blocked and can execute the signal handler.
    if sys.version_info[0] < 3:
        alive_func = g_monitor_thread.isAlive
    else:
        alive_func = g_monitor_thread.is_alive
    while alive_func():
        time.sleep(1)
    g_monitor_thread.join()


if __name__ == "__main__":
    signal.signal(signal.SIGINT, signal_handler)
    main()
