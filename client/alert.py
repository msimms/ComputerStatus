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
import signal
import smtplib
import sys
import threading
import time

g_alert_thread = None

def signal_handler(signal, frame):
    global g_alert_thread

    print "Exiting..."
    if g_alert_thread:
        g_alert_thread.terminate()

def send_sms(to, msg):
    pass

def send_email(from_addr, to_addr, msg, username, password, server):
	msg = "To:" + to_addr + "\r\nFrom: " + from_addr + "\r\nSubject:New IP Address\r\n\r\n" + msg + "\r\n\r\n"
	
	server = smtplib.SMTP(server + ':587')
	server.starttls()
	server.login(username, password)
	server.sendmail(from_addr, to_addr, msg)
	server.quit()

class AlertThread(threading.Thread):
    def __init__(self, server):
        threading.Thread.__init__(self)
        self.stopped = threading.Event()

if __name__ == "__main__":
    signal.signal(signal.SIGINT, signal_handler)

    # Parse command line options.
    parser = argparse.ArgumentParser()
    parser.add_argument("--server", type=str, action="store", default="", help="Remote logging server (optional)", required=False)

    try:
        args = parser.parse_args()
    except IOError as e:
        parser.error(e)
        sys.exit(1)

    # Start the monitor thread.
    g_alert_thread = AlertThread(args.server)
    g_alert_thread.start()

    # Wait for it to finish. We do it like this so that the main thread isn't blocked and can execute the signal handler.
    while g_alert_thread.isAlive():
        time.sleep(1)
    g_alert_thread.join()
