Automatic Conﬁguration of Routing Control Platforms (RouteFlow) in OpenFlow Networks 
==============================

This software automatically generates the virtual environment proposed for RouteFlow. The software is a modified version of RouteFlow (https://github.com/CPqD/RouteFlow/). This code is contributed by Sachin Sharma, a PhD Student at Ghent University-iMinds. Please report at Sachin.Sharma@intec.ugent.be, if you find any bug related to this code.

Papers for Reference
================================
For more information, please go through the following paper:

[1] Sachin Sharma, Dimitri Staessens, Didier Colle, Mario Pickavet and Piet Demeester, Automatic conﬁguration of routing control platforms in OpenFlow networks, ACM SIGCOMM, Vol. 43(4), pp. 491-492, 2013
 
 
The other papers using this automatic configuration framework:

[1] Sachin Sharma, Dimitri Staessens, Didier Colle, David Palma, Joao Goncalves, Mario Pickavet, Luis Cordeiro, and Piet Demeester, Demonstrating Resilient Quality of Service in Software Deﬁned Networking, IEEE INFOCOM, 2014


Software Overview
==============================

This software contains five different components:

1. RF-controller: It runs RouteFlow without any manual configuration of VMs (Linux Containers, LXCs).
2. Topology controller: It runs a topology discovery module and requires very little manual configurations. An administrator can provide following configurations to the topology controller:

  a) Range of IP addresses for the virtual environment: With this option, the administrator can specify the range of IP addresses (minimum and maximum IP address) for the virtual environment. When the topology discovery module discovers an OpenFlow link, the module chooses the IP addresses of the corresponding ports in the virtual environment from this range of IP addresses.

  b) Protocol Specific Parameters: With this option, the administrator can specify the types of protocols (e.g. OSPF, BGP etc) that need to run in the virtual environment. In addition, the administration can specify the protocol specific parameters such as the OSPF network address, the hello interval, and the router dead interval. Note that this software currently works only for OSPF. The work to make it working for other protocols is in progress.

  c) IP addresses for the non-OpenFlow links: In OpenFlow networks, some of the ports of an OpenFlow switch can be connected to hosts or switches, which are not controlled by the same controller. The administrator can assign  addresses to those ports using this option.

  d) IP addresses for the control interfaces of the virtual environment: With this option, the administrator can specify the range of IP addresses for the control interfaces of the virtual machines (e.g. LXCs). When the topology controller discovers a switch, it chooses the control IP address of the corresponding VM from this range of IP addresses. 
  
   In addition, the administrator can specify the address of the RPC server (please see the next components)
   
3. RPC (remote procedural call) client: It collects configuration information from the topology controller
and sends this to a server called RPC server.
4. RPC server: It resides in the RF-controller and configures RouteFlow on reception of configuration messages from
the RPC client.

5. FlowVisor: It acts as a proxy server between a switch and controllers (the topology controller and the RF-controller in our framework).




Building
==============================
Automatic Configuration of RouteFlow is currently tested on Ubuntu 12.04.

1.  Install the dependencies:

  sudo apt-get install build-essential git libboost-dev libboost-program-options-dev libboost-thread-dev libboost-filesystem-dev iproute-dev openvswitch-switch mongodb python-pymongo lxc ant openjdk-6-jdk python-pexpect python-ipaddr

2. Clone RouteFlow automatic configuration repository from the GitHub:
   
   git clone   ...

3. build rfclient:

   cd "the cloned directory"
   
   make rfclient

4. build flowvisor

   cd FLOWVISOR
   
   make
   
Steps to run Automatic Configuration
==============================

Before running RouteFlow, we need to write a configuration file for the topology controller, as described in Section "Software Overview". A sample file (CONFFILE) is present in folder POX_CONTROLLER.

    RPCSERVER,http,127.0.0.1,8000,
    IPADDRESS_RANGE,172.0.10.1,255.255.255.0,172.100.10.2,255.255.255.0
    CONT_IP_ADDRESS,192.169.1.101,255.255.255.0,192.169.1.255,255.255.255.0
    PROTOCOL,OSPF,ZEBRA,OSPF,OSPF
    OSPF_PARAMETERS,172.0.0.0,8,10,40
    SDPID,00-00-00-00-00-01,1,172.168.1.1,24
    SDPID,00-00-00-00-00-02,1,172.168.2.1,24
    SDPID,00-00-00-00-00-03,1,172.168.3.1,24
    SDPID,00-00-00-00-00-04,1,172.168.4.1,24
    SDPID,00-00-00-00-00-05,1,172.168.5.1,24
    SDPID,00-00-00-00-00-06,1,172.168.6.1,24

1. The RPCSERVER line gives the information about about RPCSERVER i.e. IP Address, port number etc. 
2. The IP ADDRESS_RANGE line gives the range of IP addresses from which IP addresses for an OpenFlow link (both ports of the link) will be chosen.
3. The CONT_IP_ADDRESS line gives the range of IP addresses from which an IP address for the control interface of a VM (LXC) will be chosen.
4. The PROTOCOL line gives the information about the protocols that need to run in an OpenFlow network e.g. OSPF, ZEBRA etc.
5. The OSPF_PARAMETER line gives the information about OSPF parameters such as OSPF network address, network mask length, hello interval, and router dead interval.
6. The SPID line gives the information about the external links connected with the OpenFlow network. For example, the first SPID line tells the topology controller that the first port of dpid 00-00-00-00-00-01 should have an IP address 172.168.1.1/24 


After writing the above configuration, we can run a script (called as rfauto) provided in the rftest folder:

sudo ./rfauto

This script will automatically run flowvisor, topology controller and routeflow.

For the flowvisor, config.xml is present in folder FLOWVISOR. It creates two slices: one for RouteFlow and the other for Topology Controller. With this config file, flowvisor listens on 6600. For the slices information, you can run the following command: ./scripts/fvctl.sh listSlices or any other command listed in http://archive.openflow.org/wk/index.php/OpenFlowGEC9Tutorial#Slice_your_network.


After these steps, you can start an OpenFlow network either using mininet or using a physical network. Please keep in mind that as flowvisor in above config file listens on 6600, please specify the controller port number as 6600 in the mininet or in the physical network. You can ofcourse change this number (if required).







   


