Automatic Conﬁguration of Routing Control Platforms (RouteFlow) in OpenFlow Networks 
==============================

This software automatically generates the virtual environment proposed for RouteFlow. The software is a modified version of RouteFlow (https://github.com/CPqD/RouteFlow/). 

Software Overview
==============================

This software contains five different components:

1. RF-controller: It runs RouteFlow without any manual configuration of VMs (Linux Containers, LXCs).
2. Topology controller: It runs a topology discovery module and requires very little manual configurations. An administrator can provide following manual configurations to the topology controller:

  a) Range of IP addresses for the virtual environment: With this option, the administrator can specify the range of IP addresses (minimum IP address, maximum IP address, network mask address, broadcast network address, and broadcast address) for the virtual environment, which mirrors the physical topology. When the topology discovery module discovers an OpenFlow link, the module chooses the IP addresses for the link from this range of IP addresses.

  b) Type of protocol: With this option, an administrator can specify the type of protocol (e.g. OSPF, BGP etc) that needs to run in the virtual environment. Note that this software currently only works for OSPF. The work to make it working for other protocols is in progress.

  c) IP addresses for the non-OpenFlow links: In OpenFlow networks, some of the ports of an OpenFlow switch can be connected to hosts or switches, which are not controlled by the same controllers. The administrator can assign  addresses to those ports using this option.

  d) IP addresses for the control interfaces of the virtual environment: With this option, the administrator can specify the range of IP addresses for the control interfaces of the virtual machines (e.g. LXCs). When the topology controller discovers a switch, it chooses the control IP address of the corresponding VM from this range of IP addresses. 
  
   In addition, the administrator can specify the address of the RPC server (please see the next components)
   
3. RPC (remote procedural call) client: It collects configuration information from the topology controller
and sends this to a server called RPC server.
4. RPC server: It resides in the RF-controller and configures RouteFlow on reception of configuration messages from
the RPC client.

5. FlowVisor: It acts as a proxy server between a switch and controllers (the topology controller and the RF-controller in our framework).


For more information, please go through the following paper:

 Sachin Sharma, Dimitri Staessens, Didier Colle, Mario Pickavet and Piet Demeester, Automatic conﬁguration of routing control platforms in OpenFlow networks, ACM SIGCOMM, Vol. 43(4), pp. 491-492, 2013
 
 
Building
==============================
RouteFlow runs on Ubuntu 12.04.

1.  Install the dependencies:

  sudo apt-get install build-essential git libboost-dev libboost-program-options-dev libboost-thread-dev libboost-filesystem-dev iproute-dev openvswitch-switch mongodb python-pymongo ant openjdk-6-jdk python-pexpect

2. Clone RouteFlow automatic configuration repository from the GitHub:
   
   git clone   ...

3. build rfclient:

   cd "the cloned directory"
   
   make rfclient

4. build flowvisor

   cd flowvisor
   
   make
   
   

