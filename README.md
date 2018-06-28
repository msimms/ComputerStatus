# ComputerStatus
This software is for anyone that needs to monitor their computer usage. It consists of client and server components, however, the server software is only necessary if you wish to remotely monitor your computer.

## Running the client script

Example 1: Querying the GPU every 10 minutes.
```
python client/monitor.py -gpu --interval 600
```

Example 2: Querying the GPU every 10 minutes and reporting the results to homecomputerstatus.com.
```
python client/monitor.py -gpu --interval 600 --server http://homecomputerstatus.com
```

When you run the client script on your machine, it will generate a file with the name device_id.txt. This file will contain a unique identifier for your machine. After logging in to the server, copy and paste the identifier into the Claim Device edit box to locate the data from your machine.

## Running the server
```
python server/StatusWeb.py
```

## Major Features
* Support for Nvidia GPUs (utilization and temperature)
* Ability to read CPU utilization and temperature
* Ability to read RAM utilization
* Ability to read network utilization (packets in/out)
* Ability to call external code modules when each sample is taken. This is useful for if you want ot send an email, or post a Slack message in any of the values are above or below your thresholds.

## Major Todos
* Support for AMD GPUs
* Testing with multiple GPUs

## License
This is open source software and is released under the MIT license.
