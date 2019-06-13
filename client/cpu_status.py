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

import subprocess
import platform

def win_cpu_temperature():
    try:
        import wmi

        w = wmi.WMI(namespace="root\wmi")
        temperature_info = w.MSAcpi_ThermalZoneTemperature()[0]
        return float(temperature_info.CurrentTemperature) / 10.0 - 273.15
    except ImportError:
        print("Error: Cannot read the CPU temperature because WMI is not installed.")
    except wmi.x_access_denied:
        print("Error: Access denied when trying to read the CPU temperature.")
    return 0

def mac_cpu_temperature():
    try:
        process = subprocess.Popen(['istats'], stdout=subprocess.PIPE)
        out_str, err_str = process.communicate()
        cpu_str = out_str.split('\n')[1]
        temp_str = cpu_str.split(':')[1].strip(' \t\n\r')
        temp_str = temp_str.split('\xc2')[0]
        return float(temp_str)
    except OSError:
        print("Error: Cannot read the CPU temperature because istats is not installed.")
    return 0

# Returns the CPU temperature in degrees C.
def cpu_temperature():
    target = platform.system()
    if target == 'Windows':
        return win_cpu_temperature()
    elif target == 'Darwin':
        return mac_cpu_temperature()
    return 0
