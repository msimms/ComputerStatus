[![MIT license](https://img.shields.io/badge/license-MIT-brightgreen.svg)](https://opensource.org/licenses/MIT)

# ComputerStatus
This software is for anyone that needs to monitor their computer usage. It consists of client and server components, however, the server software is only necessary if you wish to remotely monitor your computer.

## Running the client script

Example 1: Querying the GPU every 10 minutes.
```
python client/monitor.py -gpu --interval 600
```

Example 2: Querying the GPU every 10 minutes and reporting the results to the example server at https://homecomputerstatus.com.
```
python client/monitor.py -gpu --interval 600 --server https://homecomputerstatus.com
```

When you run the client script on your machine, it will generate a file with the name device_id.txt. This file will contain a unique identifier for your machine. After logging in to the server, copy and paste the identifier into the Claim Device edit box to locate the data from your machine.

## Installing the server

    git clone https://github.com/msimms/ComputerStatus.git
    cd ComputerStatus
    pip install -r server/requirements.txt
    
## Running the server

Example 1: HTTP
```
python server/start_cherrypy.py
```
or
```
python server/start_flask.py
```

Example 2: HTTPS
```
python start_cherrypy.py --cert cert.pem --privkey key.pem --https
```
or
```
python server/start_flask.py
```

Note: Passing the `--debug` flag will prevent the server from daemonizing.

## Major Features
* Support for Nvidia GPUs (utilization and temperature)
* Ability to read CPU utilization and temperature
* Ability to read RAM utilization
* Ability to read network utilization (packets in/out)
* Ability to call external code modules when each sample is taken. This is useful for if you want ot send an email, or post a Slack message in any of the values are above or below your thresholds.

## Major Todos
* Support for AMD GPUs
* Testing with multiple GPUs

## Tech
This software uses these projects to work properly:

* [pymongo](https://github.com/mongodb/mongo-python-driver) - Python interface to mongodb.
* [cherrypy](https://cherrypy.github.io/) - A framework for python-based web apps.

## License
This is open source software and is released under the MIT license.
