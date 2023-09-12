# How to Create a New Slips Module
## What is HDR and why are modules useful
HDR is a machine learning-based intrusion prevention system for Linux and MacOS, developed at the Stratosphere Laboratories from the Czech Technical University in Prague. HDR reads network traffic flows from several sources, applies multiple detections (including machine learning detections) and detects infected computers and attackers in the network. It is easy to extend the functionality of Slips by writing a new module. This blog shows how to create a new module for HDR from scratch.

## Goal of this Blog
This blog creates an example module to detect when any private IP address communicates with another private IP address. What we want is to know if, for example, the IP 192.168.4.2, is communicating with the IP 192.168.4.87. This simple idea, but still useful, is going to be the purpose of our module. Also, it will generate an alert for HDR to consider this situation. Our module will be called ```local_connection_detector```.

### High-level View of how a Module Works

The Module consists of the init() function for initializations, subscribing to channels, reading API files etc.

The main function of each module is the ```main()```,
this function is run in a while loop that keeps looping as long as
HDR is running so that the module doesn't terminate.

In case of errors in the module, the ```main()``` function should return 1 which will cause
the module to immediately terminate.

any initializations that should be run only once should be placed in the init() function
OR the ```pre_main()```. the ```pre_main()``` is a function that acts as a hook for the main function. it runs only
once and then the main starts running in a loop.
the pre-main is the place for initialization logic that cannot be done in the init, for example
dropping the root privileges from a module. we'll discuss this in more detail later.

Each module has a common ```print()``` method that handles text printing
and logging by passing everything to the
```OutputProcess.py``` for processing. the print function is implemented in the abstract module
```slips_files/common/abstracts.py ``` and used by all modules.

Each Module has its own ```shutdown_gracefully()``` function
that handles cleaning up after the module is done processing.
It handles for example:
- Saving a model before HDR stops
- Saving alerts in a .txt file if the module's job is to export alerts
- Telling the main module (HDR.py) that the module is done processing so HDR.py can kill it
etc.


## Developing a Module
When HDR runs, it automatically loads all the modules inside the ```modules/``` directory. Therefore,
our new module should be placed there.

HDR has a template module directory that we are going to copy and then modify for our purposes.

```bash
cp -a modules/template modules/local_connection_detector
```

### Changing the Name of the Module

Each module in HDR should have a name, author and description.

We should change the name inside the py file by finding the lines with the name and description in the class 'Module'
and changing them:

```python
name = 'local_connection_detector'
description = (
    'detects connections to other devices in your local network'
    )
authors = ['Your name']
```

At the end you should have a structure like this:
```
modules/
├─ local_connection_detector/
│  ├─ __init__.py
│  ├─ local_connection_detector.py
```

The __init__.py is to make sure the module is treated as a python package, don't delete it.

Remember to delete the __pycache__ dir if it's copied to the new module using:

```rm -r modules/local_connection_detector/__pycache__```


### Redis Pub/Sub

First, we need to subscribe to the channel ```new_flow```

```python
self.c1 = self.db.subscribe('new_flow')
```
and add this to the module's list of channels
```python
self.channels = {
    'new_flow': self.c1,
}
```
this list is used to get msgs from the channel later.


So now everytime slips sees a new flow, you can access it from your module using the
following line

```python
msg = self.get_msg('new_flow')
```
the implementation of the get_msg is placed in the abstract module in ```slips_files/common/abstracts.py```
and is inherited by all modules.

The above line checks if a message was received from the channel you subscribed to.

Now, you can access the content of the flow using
```python
flow = msg['data']
```

Thus far, we have the following code that gets a msg everytime slips reads a new flow

```python
def init(self):
    self.c1 = self.db.subscribe('new_ip')
    self.channels = {
        'new_ip': self.c1,
    }
```

```python
  def pre_main(self):
        """
        Initializations that run only once before the main() function runs in a loop
        """
        utils.drop_root_privs()

```

```python
 def main(self):
    """Main loop function"""
    if  msg:= self.get_msg('new_flow'):
        #TODO
        pass
```

### Detecting connections to local devices

Now that we have the flow, we need to:

- Extract the source IP
- Extract the destination IP
- Check if both of them are private
- Generate an evidence


Extracting IPs is done by the following:

```python
msg = msg['data']
msg = json.loads(msg)
flow = json.loads(msg['flow'])
uid = next(iter(flow))
flow = json.loads(flow[uid])
saddr = flow['saddr']
daddr = flow['daddr']
```

Now we need to check if both of them are private.


```python
import ipaddress
srcip_obj = ipaddress.ip_address(saddr)
dstip_obj = ipaddress.ip_address(daddr)
if srcip_obj.is_private and dstip_obj.is_private:
    pass
```

Now that we're sure both IPs are private, we need to generate an alert.

Slips requires certain info about the evidence to be able to sort them and properly display them using Kalipso.

Each parameter is described below

```python
confidence = 0.8
threat_level = 'high'
evidence_type = 'ConnectionToLocalDevice'
category = 'Anomaly.Connection'
attacker_direction = 'srcip'
attacker = saddr
description = f'Detected a connection to a local device {daddr}'
timestamp = datetime.datetime.now().strftime('%Y/%m/%d-%H:%M:%S')
profileid = msg['profileid']
twid = msg['twid']

self.db.setEvidence(evidence_type, attacker_direction, attacker, threat_level, confidence, description,
                         timestamp, category, profileid=profileid, twid=twid)
```
### Testing the Module
The module is now ready to be used.
You can copy/paste the complete code that is
[here](https://stratospherelinuxips.readthedocs.io/en/develop/create_new_module.html#complete-code)


First we start HDR by using the following command:

```bash
./HDR.py -i wlp3s0 -o local_conn_detector
```

-o is to store the output in the ```local_conn_detector/``` dir.

Then we make a connnection to a local ip

```
ping 192.168.1.18
```


And you should see your alerts in ./local_conn_detector/alerts.log by using

```
cat local_conn_detector/alerts.log
```

```
Using develop - 9f5f9412a3c941b3146d92c8cb2f1f12aab3699e - 2022-06-02 16:51:43.989778

2022/06/02-16:51:57: Src IP 192.168.1.18              . Detected Detected a connection to a local device 192.168.1.12
2022/06/02-16:51:57: Src IP 192.168.1.12              . Detected Detected a connection to a local device 192.168.1.18
```


<img src="https://raw.githubusercontent.com/stratosphereips/StratosphereLinuxIPS/develop/docs/images/module.gif"
title="Testing The Module">



### Conclusion

Due to the high modularity of HDR, adding a new HDR module is as easy as modifying a few lines in our
template module, and HDR handles running
your module and integrating it for you.

This is the [list of the modules](https://stratospherelinuxips.readthedocs.io/en/develop/detection_modules.html#detection-modules)
HDR currently have. You can enhance them, add detections, suggest new ideas using
[our Discord](https://discord.com/invite/zu5HwMFy5C) or by opening
a PR.

For more info about the threat levels, [check the docs](https://stratospherelinuxips.readthedocs.io/en/develop/architecture.html#threat-levels)

Detailed explanation of [IDEA categories here](https://idea.cesnet.cz/en/classifications)

Detailed explanation of [Slips profiles and timewindows here](https://idea.cesnet.cz/en/classifications)

[Contributing guidelines](https://stratospherelinuxips.readthedocs.io/en/develop/contributing.html)


## Complete Code
Here is the whole local_connection_detector.py code for copy/paste.

```python
from slips_files.common.imports import *
import datetime
import ipaddress
import json


class Module(Module, multiprocessing.Process):
    name = 'local_connection_detector'
    description = 'detects connections to other devices in your local network'
    authors = ['Template Author']

    def init(self)
        # To which channels do you wnat to subscribe? When a message
        # arrives on the channel the module will wakeup
        # The options change, so the last list is on the
        # slips/core/redis_database.py file. However common options are:
        # - new_ip
        # - tw_modified
        # - evidence_added
        # Remember to subscribe to this channel in redis_db/database.py
        self.c1 = self.db.subscribe('new_flow')
        self.channels = {
            'new_flow': self.c1,
            }

    def shutdown_gracefully(self):
        self.db.publish('finished_modules', self.name)

    def pre_main(self):
        """
        Initializations that run only once before the main() function runs in a loop
        """
        utils.drop_root_privs()

    def main(self):
        """Main loop function"""
        if msg := self.get_msg('new_flow'):
            msg = msg['data']
            msg = json.loads(msg)
            flow = json.loads(msg['flow'])
            uid = next(iter(flow))
            flow = json.loads(flow[uid])
            saddr = flow['saddr']
            daddr = flow['daddr']
            srcip_obj = ipaddress.ip_address(saddr)
            dstip_obj = ipaddress.ip_address(daddr)
            if srcip_obj.is_private and dstip_obj.is_private:
                confidence = 0.8
                threat_level = 'high'
                evidence_type = 'ConnectionToLocalDevice'
                category = 'Anomaly.Connection'
                attacker_direction = 'srcip'
                attacker = saddr
                description = f'Detected a connection to a local device {daddr}'
                timestamp = datetime.datetime.now().strftime('%Y/%m/%d-%H:%M:%S')
                profileid = msg['profileid']
                twid = msg['twid']

                self.db.setEvidence(
                    evidence_type, attacker_direction, attacker, threat_level,
                    confidence, description, timestamp, category, profileid=profileid,
                    twid=twid
                    )

```


## Line by Line Explanation of the Module


This section is for more detailed explanation of what each line of the module does.

```python
from slips_files.common.imports import *
```
This line imports all the common modules that need to be imported by all HDR modules in order for them to work
you can check the import here slips_files/common/imports.py
---


In order to print in your module, you simply use the following line

    self.print("some text", 1, 0)

and the text will be sent to the output queue to process, log, and print to the terminal.

---

Now here's the pre_main() function, all initializations like dropping root privs, checking for API keys, etc
should be done here

```python
utils.drop_root_privs()
 ```
the above line is responsible for dropping root privileges,
so if slips starts with sudo and the module doesn't need the root permissions, we drop them.

---

Now here's the main() function, this is the main function of each module,
it's the one that gets executed when the module starts.

All the code in this function is run in a loop as long as the module is online.

in case of an error, the module's main should return non-zero and
the module will finish execution and terminate.
if there's no errors, the module will keep looping until it runs out of msgs in the redis channels
and will call shutdown_gracefully() and terminate.


---


```python
if msg := self.get_msg('new_flow'):
```

The above line listens on the channel called ```new_flow``` that we subscribed to earlier.

The messages received in the channel are flows the HDR read by the the input process.


## Reading Input flows from an external module

HDR relies on input process for reading flows, either from an interface, a pcap, or zeek files, etc.

If you want to add your own module that reads flows from somehwere else,
for example from a simulation framework like the CYST module,
you can easily do that using the ```--input-module <module_name>``` parameter

Reading flows should be handeled by that module, then sent to the inputprocess for processing using the
```new_module_flow``` channel.

For now, this feature only supports reading flows in zeek json format, but feel free to extend it.


### How to shutdown_gracefully()

The ```stop_message ``` is sent from the main slips.py to the ```control_module``` channel
to tell all modules
that slips is stopping and the modules should finish all the processing it's
doing and shutdown.

So, for example if you're training a ML model in your module,
and you want to save it before the module stops,

You should place your save_model() function in the shutdown_gracefully() function, right before the module
announces its name as finished in the ```finished_modules``` channel

Inside shutdown_gracefully() we have the following line, This is the module,
responding to the stop_message, telling slips.py that it successfully finished processing and
is ready to be killed.

```python
self.db.publish('finished_modules', self.name)

```

### Troubleshooting
Most errors occur when running the module inside SLIPS.
These errors are hard to resolve, because warnings and debug messages may be hidden
under extensive outputs from other modules.

If the module does not start at all, make sure it is not disabled in the
config/slips.conf file. If that is not the case, check that
the \_\_init\_\_.py file is present in module directory, and read
the output files (errors.log and slips.log) - if there were any errors
(eg. import errors), they would prevent the module from starting.


In case that the module is started, but does not receive any messages from
the channel, make sure that:

	-The channel is properly subscribed to in the module

	-Messages are being sent in this channel

	-Other modules subscribed to the channel get the message

    - the channel name is present in the supported_channels list in redis_db/database.py

### Testing


HDR has 2 kinds of tests, unit tests and integration tests.

integration tests are done by testing all files in our ```dataset/``` dir and
are done in ```tests/test_dataset.py```

Before pushing, run the unit tests and integration tests by:


1- Make sure you're in HDR main dir (the one with kalipso.sh)


2- Run all tests ```./tests/run_all_tests.sh```

HDR supports the -P flag to run redis on your port of choice. this flag is
used so that HDR can keep track of the ports it opened while testing and close them later.

### Adding your own unit tests

HDR uses ```pytest``` as the main testing framework, You can add your own unit tests by:

1- create a file called ```test_module_name.py``` in the ```tests/``` dir


2- create a method for initializing your module in ```tests/module_factory.py```


3- every function should start with ```test_```


4- go to the main slips dir and run ```./tests/run_all_tests.sh``` and every test file in the ```tests/``` dir will run

### Getting in touch

Feel free to join our [Discord server](https://discord.gg/zu5HwMFy5C) and ask questions, suggest new features or give us feedback.

PRs and Issues are welcomed in our repo.

### Conclusion

Adding a new feature to HDR is an easy task. The template is ready for everyone to use and there is not much to learn about HDR to be able to write a module.

If you wish to add a new module to the Slips repository, issue a pull request and wait for a review.
