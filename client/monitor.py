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
import signal
import threading

g_args = None
g_gpu_statusing_enabled = False
g_stop_flag = None

try:
    import GPUtil
    g_gpu_statusing_enabled = True
except:
    print "Error: Could not import import GPUtil. GPU Statusing will be disabled."

def signal_handler(signal, frame):
    print "Exiting..."
    if g_stop_flag:
        g_stop_flag.set()

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
        print cpu_percent + "% CPU"
        virt_mem = psutil.virtual_memory()
        cpu_times = psutil.cpu_times()

    def run(self):
        global g_args

        while not self.stopped.wait(g_args.interval):
            self.check_cpu()
            self.check_gpu()

if __name__ == "__main__":
    
    signal.signal(signal.SIGINT, signal_handler)

    # Parse command line options.
    parser = argparse.ArgumentParser()
    parser.add_argument("--interval", type=int, default=60, help="Frequency (in seconds) in which to sample.", required=False)
    parser.add_argument("--cpu", action="store_true", default=True, help="TRUE if sampling the CPU", required=False)
    parser.add_argument("--gpu", action="store_true", default=False, help="TRUE if sampling the GPU (Nvidia only)", required=False)
    parser.add_argument("--server", type=str, action="store", default="", help="Remote logging server (optional)", required=False)

    try:
        g_args = parser.parse_args()
    except IOError as e:
        parser.error(e)
        sys.exit(1)

    # Start the monitor thread.
    g_stop_flag = threading.Event()
    monitor_thread = MonitorThread(g_stop_flag)
    monitor_thread.start()
