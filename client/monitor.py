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
import datetime
import os
import requests
import signal
import sys
import threading
import time
import psutil
import uuid

g_gpu_statusing_enabled = False
g_monitor_thread = None

def signal_handler(signal, frame):
    global g_monitor_thread

    print "Exiting..."
    if g_monitor_thread:
        g_monitor_thread.terminate()

class MonitorThread(threading.Thread):
    def __init__(self, interval, server, verbose, do_cpu_check, do_mem_check, do_gpu_check):
        threading.Thread.__init__(self)
        self.stopped = threading.Event()
        self.interval = interval
        self.server = server
        self.verbose = verbose
        self.do_cpu_check = do_cpu_check
        self.do_mem_check = do_mem_check
        self.do_gpu_check = do_gpu_check

        if self.server:
            # Look for device ID file; generate one if not found.
            self.device_id = None
            if os.path.isfile('device_id.txt'):
                with open('device_id.txt', 'r') as device_id_file:
                    self.device_id = device_id_file.read()
            if self.device_id is None:
                self.device_id = str(uuid.uuid4())
                with open('device_id.txt', 'w') as device_id_file:
                    device_id_file.write(self.device_id)

    def terminate(self):
        print "Terminating..."
        self.stopped.set()

    # Sends the values to the server for archival.
    def send_to_server(self, values):
        try:
            values['device_id'] = self.device_id
            values['datetime'] = datetime.datetime.utcnow().strftime("%s")
            url = self.server + "/api/1.0/upload"
            r = requests.post(url, data=values)
            print r
        except:
            pass

    # Appends GPU values to the 'values' dictionary.
    def check_gpu(self, values):
        global g_gpu_statusing_enabled

        if not g_gpu_statusing_enabled:
            return

        try:
            all_gpus = GPUtil.getGPUs()
            for g in all_gpus:
                values['gpu - percent'] = g.usage
        except:
            pass

    # Appends current CPU values to the 'values' dictionary.
    def check_cpu(self, values):
        cpu_percent = psutil.cpu_percent()
        values['cpu - percent'] = cpu_percent
        cpu_times = psutil.cpu_times()
        values['cpu - user times'] = cpu_times.user

    # Appends current memory values to the 'values' dictionary.
    def check_mem(self, values):
        virt_mem = psutil.virtual_memory()
        values['virtual memory - total'] = virt_mem.total
        values['virtual memory - percent'] = virt_mem.percent

    def run(self):
        while not self.stopped.wait(self.interval):
            values = {}
            if self.do_cpu_check:
                self.check_cpu(values)
            if self.do_mem_check:
                self.check_mem(values)
            if self.do_gpu_check:
                self.check_gpu(values)
            if self.server:
                self.send_to_server(values)
            if self.verbose:
                print values

if __name__ == "__main__":
    signal.signal(signal.SIGINT, signal_handler)

    # Parse command line options.
    parser = argparse.ArgumentParser()
    parser.add_argument("--interval", type=int, default=60, help="Frequency (in seconds) at which to sample.", required=False)
    parser.add_argument("--server", type=str, action="store", default="", help="Remote logging server (optional)", required=False)
    parser.add_argument("--verbose", action="store_true", default=True, help="TRUE to enable verbose mode", required=False)
    parser.add_argument("--cpu", action="store_true", default=True, help="TRUE if sampling the CPU", required=False)
    parser.add_argument("--mem", action="store_true", default=True, help="TRUE if sampling memory", required=False)
    parser.add_argument("--gpu", action="store_true", default=False, help="TRUE if sampling the GPU (Nvidia only)", required=False)

    try:
        import GPUtil
        g_gpu_statusing_enabled = True
    except:
        print "Error: Could not import import GPUtil. GPU Statusing will be disabled."

    try:
        args = parser.parse_args()
    except IOError as e:
        parser.error(e)
        sys.exit(1)

    # Start the monitor thread.
    g_monitor_thread = MonitorThread(args.interval, args.server, args.verbose, args.cpu, args.mem, args.gpu)
    g_monitor_thread.start()

    # Wait for it to finish. We do it like this so that the main thread isn't blocked and can execute the signal handler.
    while (g_monitor_thread.isAlive()):
        time.sleep(1)
    g_monitor_thread.join()
