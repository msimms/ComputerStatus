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
import psutil
import threading

g_args = None
g_gpu_statusing_enabled = False

try:
    import GPUtil
    g_gpu_statusing_enabled = True
except:
    print "Error: Could not import import GPUtil. GPU Statusing will be disabled."

class MonitorThread(threading.Thread):
    def __init__(self, event):
        threading.Thread.__init__(self)
        self.stopped = event

    def check_gpu(self):
        global g_gpu_statusing_enabled

        if not g_gpu_statusing_enabled:
            return
        try:
            GPUtil.showUtilization()
        except:
            pass

    def check_cpu(self):
        cpu_percent = psutil.cpu_percent()
        print cpu_percent
        virt_mem = psutil.virtual_memory()
        cpu_times = psutil.cpu_times()

    def run(self):
        global g_args

        while not self.stopped.wait(g_args.interval):
            self.check_cpu()
            self.check_gpu()

# Parse command line options.
parser = argparse.ArgumentParser()
parser.add_argument("--interval", type=int, default=60, help="Frequency (in seconds) in which to sample.", required=False)
parser.add_argument("--cpu", action="store_true", default=True, help="TRUE if sampling the CPU", required=False)
parser.add_argument("--gpu", action="store_true", default=False, help="TRUE if sampling the GPU (Nvidia only)", required=False)

try:
    g_args = parser.parse_args()
except IOError as e:
    parser.error(e)
    sys.exit(1)

# Start the monitor thread.
stop_flag = threading.Event()
monitor_thread = MonitorThread(stop_flag)
monitor_thread.start()
#stop_flag.set()
