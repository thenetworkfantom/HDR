.. image:: /images/slips_logo.png
    :align: center

HDR
============================

The tool is available on GitHub `here <https://github.com/stratosphereips/StratosphereLinuxIPS/tree/master>`_.

**HDR** is a Python-based intrusion prevention system that uses machine learning to detect malicious behaviors in the network traffic. HDR was designed to focus on targeted attacks, to detect of command and control channelsi, and to provide good visualisation for the analyst. HDR is able to analyze real live traffic from the device and the large network captures in the type of a pcap files, Suricata, Zeek/Bro and Argus flows. As a result, HDR highlights suspicious behaviour and connections that needs to be deeper analyzed.

This documentation gives an overview how HDR works, how to use it and how to help. To be specific, that table of contents goes as follows:


- **Installation**. Instructions to install HDR in a Docker and in a computer. See :doc:`Installation <installation>`.

- **Usage**. Instructions and examples how to run HDR with different type of files and analyze the traffic using HDR and its GUI Kalipso. See :doc:`Usage <usage>`.

- **Detection modules**. Explanation of detection modules in HDR, types of input and output. See :doc:`Detection modules <detection_modules>`.

- **Architecture**. Internal architecture of HDR (profiles, timewindows), the use of Zeek and connection to Redis. See :doc:`Architecture <architecture>`.

- **Training with your own data**. Explanation on how to re-train the machine learning system of HDR with your own traffic (normal or malicious).See :doc:`Training <training>`.

- **Detections per Flow**. Explanation on how HDR works to make detections on each flow with different techniques. See :doc:`Flow Alerts <flowalerts>`.

- **Exporting**. The exporting module allows HDR to export to Slack and STIX servers. See :doc:`Exporting <exporting>`.

- **HDR in Action**. Example of using slips to analyze different PCAPs See :doc:`HDR in action <slips_in_action>`.

- **Contributing**. Explanation how to contribute to HDR, and instructions how to implement new detection module in HDR. See :doc:`Contributing <contributing>`.

- **Create a new module**. Step by step guide on how to create a new HDR module See :doc:`Create a new module <create_new_module>`.

- **Code documentation**. Auto generated slips code documentation See :doc:`Code docs <code_documentation>`.





.. toctree::
   :maxdepth: 2
   :hidden:
   :caption: HDR

   self
   installation
   usage
   architecture
   detection_modules
   flowalerts
   features
   training
   exporting
   P2P
   slips_in_action
   contributing
   create_new_module
   FAQ
   code_documentation


