# Copyright 2011-2013 James McCauley
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# This file is loosely based on the discovery component in NOX.

"""
This module discovers the connectivity between OpenFlow switches by sending
out LLDP packets. To be notified of this information, listen to LinkEvents
on core.openflow_discovery.

It's possible that some of this should be abstracted out into a generic
Discovery module, or a Discovery superclass.
"""
from pox.core import core
import pox
import pox.lib.util
import ipaddr
from pox.lib.revent import *
from pox.lib.recoco import Timer
from pox.lib.util import dpid_to_str, str_to_bool
from pox.core import core
import pox.openflow.libopenflow_01 as of
import pox.lib.packet as pkt
import xmlrpclib
import sys

import struct
import time
from collections import namedtuple
from random import shuffle
from rflib.defs import *

log = core.getLogger()

configfile = file("CONFFILE")
found=0
controlIP=[0,0,0,0]
controlMask=[0,0,0,0]
controlNet=[0,0,0,0]
controlBroad=[0,0,0,0]
controlIndex=3
protocol=["OSPF","OSPF","OSPF","OSPF"]
minIPaddress=[0,0,0,0]
maxIPaddress=[0,0,0,0]
linkSrcIPaddress=[0,0,0,0]
linkDstIPaddress=[0,0,0,0]
maxIPNum=1
maxConIPNum=1
net=[0,0,0,0]
broad=[0,0,0,0]
network={}
protoI=[0,0,0,0]
masklength=1
configure={}
entries = [line.strip("\n").split(",") for line in configfile.readlines()[0:]]
for (a,b,c,d,e) in entries:
  if a=="RPCSERVER":
     found=1
     http=b
     serverip=c
     serverport=d
  if a=="CONT_IP_ADDRESS":
     controlIP=b.split(".")
     controlMask=c.split(".")
     networkstr = str(b) + "/" + str(c);
     address = ipaddr.IPv4Network(networkstr)
     controlNet = str(address.network)
     controlBroad = str(address.broadcast)
     maxConIPNum = int(ipaddr.IPv4Address(unicode(d)))
  if a=="PROTOCOL":
     protocol[0]=b
     protocol[1]=c
     protocol[2]=d
     protocol[3]=e

  if a=="OSPF_PARAMETERS":
     network[b]=c
     protoI[0] = d
     protoI[1] = e
 
  if a=="IPADDRESS_RANGE":
     minIPaddress = linkSrcIPaddress= b.split(".") 
     linkDstIPaddress[0] = linkSrcIPaddress[0]
     linkDstIPaddress[1] = linkSrcIPaddress[1]
     linkDstIPaddress[2] = linkSrcIPaddress[2]
     linkDstIPaddress[3] = str(int(linkSrcIPaddress[3]) + 1)
     minNetMask=c.split(".")
     networkstr = str(b) + "/" + str(c);
     address = ipaddr.IPv4Network(networkstr)
     net = str(address.network)
     masklength = str(address.prefixlen)
     broad = str(address.broadcast)
     maxIPaddress = d.split(".")
     maxNetMask = e.split(".")
     maxIPNum = int(ipaddr.IPv4Address(unicode(d)))
  if a=="SDPID":
     if b in configure:
	nam=configure[b]
	configure[b]=nam+ ",NEW" + "," + c + "," + d + "," + e
     else:
	configure[b]= "NEW," + c + ","+ d + "," + e
if found==0:
   print "RPC Server address is not found"
   
address=http+"://"+serverip+":"+serverport
print address  
print configure.keys()
#XMLRproxy = xmlrpclib.ServerProxy(address);      
XMLRproxy = xmlrpclib.ServerProxy('http://localhost:8000');      
     

class LLDPSender (object):
  """
  Sends out discovery packets
  """

  SendItem = namedtuple("LLDPSenderItem", ('dpid','port_num','packet'))

  #NOTE: This class keeps the packets to send in a flat list, which makes
  #      adding/removing them on switch join/leave or (especially) port
  #      status changes relatively expensive. Could easily be improved.

  def __init__ (self, send_cycle_time, ttl = 120):
    """
    Initialize an LLDP packet sender

    send_cycle_time is the time (in seconds) that this sender will take to
      send every discovery packet.  Thus, it should be the link timeout
      interval at most.

    ttl is the time (in seconds) for which a receiving LLDP agent should
      consider the rest of the data to be valid.  We don't use this, but
      other LLDP agents might.  Can't be 0 (this means revoke).
    """
    # Packets remaining to be sent in this cycle
    self._this_cycle = []

    # Packets we've already sent in this cycle
    self._next_cycle = []

    self._timer = None
    self._ttl = ttl
    self._send_cycle_time = send_cycle_time
    core.listen_to_dependencies(self)

  def _handle_openflow_PortStatus (self, event):
    """
    Track changes to switch ports
    """
    if event.added:
      self.add_port(event.dpid, event.port, event.ofp.desc.hw_addr)
    elif event.deleted:
      self.del_port(event.dpid, event.port)

  def _handle_openflow_ConnectionUp (self, event):
    if is_rfvs(event.dpid):
	return

    self.del_switch(event.dpid, set_timer = False)
    ipNum=int(ipaddr.IPv4Address(unicode(controlIP[0]+"."+controlIP[1]+"."+controlIP[2]+"."+controlIP[3])))
    if(maxConIPNum - ipNum > 0):
    	ports = [(p.port_no, p.hw_addr) for p in event.ofp.ports]
    	datapathidd=pox.lib.util.dpidToStr(event.dpid)
    	join="\"join,"+datapathidd+","+str(len(ports))+","+str(controlIP[0])+"." +str(controlIP[1])+"." +str(controlIP[2])+"." +str(controlIP[3])
	join=join+ ","+str(controlMask[0])+"." +str(controlMask[1])+"." +str(controlMask[2])+"." +str(controlMask[3])
	join=join+ ","+str(controlNet) + ","+str(controlBroad) 
	join=join+",PR,"+protocol[0]+",PR,"+protocol[1] + ",PRN" 
#this can be extended further as more than two protocol can be used in a single vm
	for netw in network:
	    join = join + ",NETWORK,"+netw+","+ network[netw]
	    join = join + ",HELLO_INTERVAL,"+protoI[0]+",ROUTER_DEAD_INTERVAL,"+ protoI[1]
	    if datapathidd in configure:
	    	join = join + ","+configure[datapathidd]

	join= join + ",\""
	print join 
	global XMLRproxy
	XMLRproxy.RPCSERVER_PERFORM_ACTION(join)

	controlIP[3]= str(int(controlIP[3]) +1)
	if(int(controlIP[3]) >=255):
		controlIP[2] = str(int(controlIP[2]) +1)
		controlIP[3] = str(1)
		if(int(controlIP[2]) >= 255):
			controlIP[1] =  str(int(controlIP[1]) +1)
			controlIP[2] = str(1)
			controlIP[3] = str(1)
			if(int(controlIP[1]) >=255):
				controlIP[0] =  str(int(controlIP[0]) +1)
				controlIP[1] =  str(1)
				controlIP[2] =  str(1)
				controlIP[3] =  str(1)
				if(int(controlIP[0]) >=255):
					log.info('All the range of control IP address is finished; We cannot configure any other VM now')

    else:
	log.info('Switch Join Event received: all the range of control IP addresses is finished; we cannot configure any other VM now')

    for port_num, port_addr in ports:
      self.add_port(event.dpid, port_num, port_addr, set_timer = False)

    self._set_timer()

  def _handle_openflow_ConnectionDown (self, event):
    self.del_switch(event.dpid)
    

  def del_switch (self, dpid, set_timer = True):
    self._this_cycle = [p for p in self._this_cycle if p.dpid != dpid]
    self._next_cycle = [p for p in self._next_cycle if p.dpid != dpid]
    if set_timer: self._set_timer()

  def del_port (self, dpid, port_num, set_timer = True):
    if port_num > of.OFPP_MAX: return
    self._this_cycle = [p for p in self._this_cycle
                        if p.dpid != dpid or p.port_num != port_num]
    self._next_cycle = [p for p in self._next_cycle
                        if p.dpid != dpid or p.port_num != port_num]
    if set_timer: self._set_timer()

  def add_port (self, dpid, port_num, port_addr, set_timer = True):
    if port_num > of.OFPP_MAX: return
    self.del_port(dpid, port_num, set_timer = False)
    self._next_cycle.append(LLDPSender.SendItem(dpid, port_num,
          self.create_discovery_packet(dpid, port_num, port_addr)))
    if set_timer: self._set_timer()

  def _set_timer (self):
    if self._timer: self._timer.cancel()
    self._timer = None
    num_packets = len(self._this_cycle) + len(self._next_cycle)
    if num_packets != 0:
      self._timer = Timer(self._send_cycle_time / float(num_packets),
                          self._timer_handler, recurring=True)

  def _timer_handler (self):
    """
    Called by a timer to actually send packets.

    Picks the first packet off this cycle's list, sends it, and then puts
    it on the next-cycle list.  When this cycle's list is empty, starts
    the next cycle.
    """
    if len(self._this_cycle) == 0:
      self._this_cycle = self._next_cycle
      self._next_cycle = []
      shuffle(self._this_cycle)
    item = self._this_cycle.pop(0)
    self._next_cycle.append(item)
    core.openflow.sendToDPID(item.dpid, item.packet)

  def create_discovery_packet (self, dpid, port_num, port_addr):
    """
    Build discovery packet
    """

    chassis_id = pkt.chassis_id(subtype=pkt.chassis_id.SUB_LOCAL)
    chassis_id.id = bytes('dpid:' + hex(long(dpid))[2:-1])
    # Maybe this should be a MAC.  But a MAC of what?  Local port, maybe?

    port_id = pkt.port_id(subtype=pkt.port_id.SUB_PORT, id=str(port_num))

    ttl = pkt.ttl(ttl = self._ttl)

    sysdesc = pkt.system_description()
    sysdesc.payload = bytes('dpid:' + hex(long(dpid))[2:-1])

    discovery_packet = pkt.lldp()
    discovery_packet.tlvs.append(chassis_id)
    discovery_packet.tlvs.append(port_id)
    discovery_packet.tlvs.append(ttl)
    discovery_packet.tlvs.append(sysdesc)
    discovery_packet.tlvs.append(pkt.end_tlv())

    eth = pkt.ethernet(type=pkt.ethernet.LLDP_TYPE)
    eth.src = port_addr
    eth.dst = pkt.ETHERNET.NDP_MULTICAST
    eth.payload = discovery_packet

    po = of.ofp_packet_out(action = of.ofp_action_output(port=port_num))
    po.data = eth.pack()
    return po.pack()


class LinkEvent (Event):
  """
  Link up/down event
  """
  def __init__ (self, add, link):
    Event.__init__(self)
    self.link = link
    self.added = add
    self.removed = not add

  def port_for_dpid (self, dpid):
    if self.link.dpid1 == dpid:
      return self.link.port1
    if self.link.dpid2 == dpid:
      return self.link.port2
    return None


class Link (namedtuple("LinkBase",("dpid1","port1","dpid2","port2"))):
  @property
  def uni (self):
    """
    Returns a "unidirectional" version of this link

    The unidirectional versions of symmetric keys will be equal
    """
    pairs = list(self.end)
    pairs.sort()
    return Link(pairs[0][0],pairs[0][1],pairs[1][0],pairs[1][1])

  @property
  def end (self):
    return ((self[0],self[1]),(self[2],self[3]))

  def __str__ (self):
    return "%s.%s -> %s.%s" % (dpid_to_str(self[0]),self[1],
                               dpid_to_str(self[2]),self[3])

  def __repr__ (self):
    return "Link(dpid1=%s,port1=%s, dpid2=%s,port2=%s)" % (self.dpid1,
        self.port1, self.dpid2, self.port2)


class Discovery (EventMixin):
  """
  Component that attempts to discover network toplogy.

  Sends out specially-crafted LLDP packets, and monitors their arrival.
  """

  _flow_priority = 65000     # Priority of LLDP-catching flow (if any)
  _link_timeout = 20        # How long until we consider a link dead
  _timeout_check_period = 5  # How often to check for timeouts

  _eventMixin_events = set([
    LinkEvent,
  ])

  _core_name = "openflow_discovery" # we want to be core.openflow_discovery

  Link = Link

  def __init__ (self, install_flow = True, explicit_drop = True,
                link_timeout = None, eat_early_packets = False):
    self._eat_early_packets = eat_early_packets
    self._explicit_drop = explicit_drop
    self._install_flow = install_flow
    if link_timeout: self._link_timeout = link_timeout

    self.adjacency = {} # From Link to time.time() stamp
    self._sender = LLDPSender(self.send_cycle_time)

    # Listen with a high priority (mostly so we get PacketIns early)
    core.listen_to_dependencies(self,
        listen_args={'openflow':{'priority':0xffffffff}})

    Timer(self._timeout_check_period, self._expire_links, recurring=True)

  @property
  def send_cycle_time (self):
    return self._link_timeout / 2.0

  def install_flow (self, con_or_dpid, priority = None):
    if priority is None:
      priority = self._flow_priority
    if isinstance(con_or_dpid, (int,long)):
      con = core.openflow.connections.get(con_or_dpid)
      if con is None:
        log.warn("Can't install flow for %s", dpid_to_str(con_or_dpid))
        return False
    else:
      con = con_or_dpid

    match = of.ofp_match(dl_type = pkt.ethernet.LLDP_TYPE,
                          dl_dst = pkt.ETHERNET.NDP_MULTICAST)
    msg = of.ofp_flow_mod()
    msg.priority = priority
    msg.match = match
    msg.actions.append(of.ofp_action_output(port = of.OFPP_CONTROLLER))
    con.send(msg)
    return True

  def _handle_openflow_ConnectionUp (self, event):
    if self._install_flow:
      # Make sure we get appropriate traffic
      log.debug("Installing flow for %s", dpid_to_str(event.dpid))
      self.install_flow(event.connection)

  def _handle_openflow_ConnectionDown (self, event):
    # Delete all links on this switch
    self._delete_links([link for link in self.adjacency
                        if link.dpid1 == event.dpid
                        or link.dpid2 == event.dpid])

  def _expire_links (self):
    """
    Remove apparently dead links
    """
    now = time.time()
    return
    expired = [link for link,timestamp in self.adjacency.iteritems()
               if timestamp + self._link_timeout < now]
    if expired:
      for link in expired:
        log.info('link timeout: %s', link)

      self._delete_links(expired)

  def _handle_openflow_PacketIn (self, event):
    """
    Receive and process LLDP packets
    """

    packet = event.parsed

    if (packet.effective_ethertype != pkt.ethernet.LLDP_TYPE
        or packet.dst != pkt.ETHERNET.NDP_MULTICAST):
      if not self._eat_early_packets: return
      if not event.connection.connect_time: return
      enable_time = time.time() - self.send_cycle_time - 1
      if event.connection.connect_time > enable_time:
        return EventHalt
      return

    if self._explicit_drop:
      if event.ofp.buffer_id is not None:
        log.debug("Dropping LLDP packet %i", event.ofp.buffer_id)
        msg = of.ofp_packet_out()
        msg.buffer_id = event.ofp.buffer_id
        msg.in_port = event.port
        event.connection.send(msg)

    lldph = packet.find(pkt.lldp)
    if lldph is None or not lldph.parsed:
      log.error("LLDP packet could not be parsed")
      return EventHalt
    if len(lldph.tlvs) < 3:
      log.error("LLDP packet without required three TLVs")
      return EventHalt
    if lldph.tlvs[0].tlv_type != pkt.lldp.CHASSIS_ID_TLV:
      log.error("LLDP packet TLV 1 not CHASSIS_ID")
      return EventHalt
    if lldph.tlvs[1].tlv_type != pkt.lldp.PORT_ID_TLV:
      log.error("LLDP packet TLV 2 not PORT_ID")
      return EventHalt
    if lldph.tlvs[2].tlv_type != pkt.lldp.TTL_TLV:
      log.error("LLDP packet TLV 3 not TTL")
      return EventHalt

    def lookInSysDesc ():
      r = None
      for t in lldph.tlvs[3:]:
        if t.tlv_type == pkt.lldp.SYSTEM_DESC_TLV:
          # This is our favored way...
          for line in t.payload.split('\n'):
            if line.startswith('dpid:'):
              try:
                return int(line[5:], 16)
              except:
                pass
          if len(t.payload) == 8:
            # Maybe it's a FlowVisor LLDP...
            # Do these still exist?
            try:
              return struct.unpack("!Q", t.payload)[0]
            except:
              pass
          return None

    originatorDPID = lookInSysDesc()

    if originatorDPID == None:
      # We'll look in the CHASSIS ID
      if lldph.tlvs[0].subtype == pkt.chassis_id.SUB_LOCAL:
        if lldph.tlvs[0].id.startswith('dpid:'):
          # This is how NOX does it at the time of writing
          try:
            originatorDPID = int(lldph.tlvs[0].id[5:], 16)
          except:
            pass
      if originatorDPID == None:
        if lldph.tlvs[0].subtype == pkt.chassis_id.SUB_MAC:
          # Last ditch effort -- we'll hope the DPID was small enough
          # to fit into an ethernet address
          if len(lldph.tlvs[0].id) == 6:
            try:
              s = lldph.tlvs[0].id
              originatorDPID = struct.unpack("!Q",'\x00\x00' + s)[0]
            except:
              pass

    if originatorDPID == None:
      log.warning("Couldn't find a DPID in the LLDP packet")
      return EventHalt

    if originatorDPID not in core.openflow.connections:
      log.info('Received LLDP packet from unknown switch')
      return EventHalt

    # Get port number from port TLV
    if lldph.tlvs[1].subtype != pkt.port_id.SUB_PORT:
      log.warning("Thought we found a DPID, but packet didn't have a port")
      return EventHalt
    originatorPort = None
    if lldph.tlvs[1].id.isdigit():
      # We expect it to be a decimal value
      originatorPort = int(lldph.tlvs[1].id)
    elif len(lldph.tlvs[1].id) == 2:
      # Maybe it's a 16 bit port number...
      try:
        originatorPort  =  struct.unpack("!H", lldph.tlvs[1].id)[0]
      except:
        pass
    if originatorPort is None:
      log.warning("Thought we found a DPID, but port number didn't " +
                  "make sense")
      return EventHalt

    if (event.dpid, event.port) == (originatorDPID, originatorPort):
      log.warning("Port received its own LLDP packet; ignoring")
      return EventHalt

    link = Discovery.Link(originatorDPID, originatorPort, event.dpid,
                          event.port)
    link2 = Discovery.Link(event.dpid,event.port, originatorDPID, originatorPort) #assuming the bidirectional link

    if link not in self.adjacency:
      self.adjacency[link] = time.time()
      self.adjacency[link2] = time.time()
      log.info('link detected: %s', link)
      self.raiseEventNoErrors(LinkEvent, True, link)
      self.raiseEventNoErrors(LinkEvent, True, link2)
      dpid1=pox.lib.util.dpidToStr(link.dpid1)
      dpid2=pox.lib.util.dpidToStr(link.dpid2)
      ipNum=int(ipaddr.IPv4Address(unicode(linkDstIPaddress[0]+"."+linkDstIPaddress[1]+"."+linkDstIPaddress[2]+"."+linkDstIPaddress[3])))
      if(maxIPNum - ipNum > 0):
      		pstr="\"link,"+dpid1+","+str(link.port1)+","+linkSrcIPaddress[0]+"."+linkSrcIPaddress[1]+"."+linkSrcIPaddress[2]+"."+linkSrcIPaddress[3] 
      		pstr=pstr+ ","+str(minNetMask[0])+"." +str(minNetMask[1])+"." +str(minNetMask[2])+"." +str(minNetMask[3])
      		networkstr = linkSrcIPaddress[0]+"."+linkSrcIPaddress[1]+"."+linkSrcIPaddress[2]+"."+ linkSrcIPaddress[3] + "/" + str(minNetMask[0])+"." +str(minNetMask[1])+"." +str(minNetMask[2])+"." +str(minNetMask[3])
      		address = ipaddr.IPv4Network(networkstr)

      		pstr=pstr+ ","+str(address.network) + ","+str(address.broadcast)
      		pstr=pstr+","+dpid2+","+str(link.port2)+","+linkDstIPaddress[0]+"."+linkDstIPaddress[1]+"."+ linkDstIPaddress[2]+"."+linkDstIPaddress[3] 
      		pstr=pstr+ ",\""
      		print pstr
     		XMLRproxy.RPCSERVER_PERFORM_ACTION(pstr)
      		if int(linkSrcIPaddress[2])<=255:
			linkSrcIPaddress[2]=str(int(linkSrcIPaddress[2])+1)
	 		linkDstIPaddress[2]=linkSrcIPaddress[2]
      		else:
	 		if int(linkSrcIPaddress[1])<=255:
	 			linkSrcIPaddress[1]=str(int(linkSrcIPaddress[1])+1)
	 			linkDstIPaddress[1]=linkSrcIPaddress[1]
	 		else:
	 			if int(linkSrcIPaddress[0])<=255:
	 				linkSrcIPaddress[0]=str(int(linkSrcIPaddress[0])+1)
	 				linkDstIPaddress[0]=linkSrcIPaddress[0]
				else:
					print "Ops, no ip address has left"
      else:
		print "Ops, no ip address has left"
	 
    else:
      # Just update timestamp
      self.adjacency[link] = time.time()
      self.adjacency[link2] = time.time() 

    return EventHalt # Probably nobody else needs this event

  def _delete_links (self, links):
    for link in links:
      self.raiseEventNoErrors(LinkEvent, False, link)
    for link in links:
      self.adjacency.pop(link, None)

  def is_edge_port (self, dpid, port):
    """
    Return True if given port does not connect to another switch
    """
    for link in self.adjacency:
      if link.dpid1 == dpid and link.port1 == port:
        return False
      if link.dpid2 == dpid and link.port2 == port:
        return False
    return True


def launch (no_flow = False, explicit_drop = True, link_timeout = None,
            eat_early_packets = False):
  explicit_drop = str_to_bool(explicit_drop)
  eat_early_packets = str_to_bool(eat_early_packets)
  install_flow = not str_to_bool(no_flow)
  if link_timeout: link_timeout = int(link_timeout)

  core.registerNew(Discovery, explicit_drop=explicit_drop,
                   install_flow=install_flow, link_timeout=link_timeout,
                   eat_early_packets=eat_early_packets)
