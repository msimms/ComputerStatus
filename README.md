# ComputerStatus
Do you need to remotely monitor your computer usage? This project is a combination of a client side python script and a small web service for remotely monitoring CPU, GPU, and RAM usage.

When used with the corresponding python script, this allows you to remotely monitor CPU, GPU, RAM, and network utilization.

You can get a copy of the corresponding <a href="https://github.com/msimms/ComputerStatus/blob/master/client/monitor.py">client script</a> from <a href="github.com">github.com</a> and run it on the computer you wish to monitor (you'll also need to have python installed, of course). Since the client software is distributed as a python script, it will run on most commonly available operating systems. This includes Windows, Linux, and Mac OS.

When you run the client script on your machine, it will generate a file with the name device_id.txt. This file will contain a unique identifier for your machine. After logging in, copy and paste the identifier into the Claim Device edit box to locate the data from your machine.

This is open source software and is released under the MIT license.
