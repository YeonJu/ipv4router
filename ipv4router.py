#!/usr/bin/env python

'''
    Basic IPv4 router (static routing) in Python
    '''
import time
import sys
import os
import os.path
sys.path.append(os.path.join(os.environ['HOME'],'pox'))
sys.path.append(os.path.join(os.getcwd(),'pox'))
import pox.lib.packet as pktlib
from pox.lib.packet import ethernet,ETHER_BROADCAST,IP_ANY
from pox.lib.packet import arp
from pox.lib.addresses import netmask_to_cidr, EthAddr,IPAddr
from srpy_common import log_info, log_debug, log_warn, SrpyShutdown, SrpyNoPackets, debugger
from firewall import Firewall

class packt(object):
    def __init__(self, mypkt):
        self.retries = 0
        self.time = 0
        self.pktElem = mypkt

class Router(object):
    def __init__(self, net):
        self.net = net
        self.intf_list = net.interfaces()
        self.interface = {}
        self.devInterface = {}
    	self.ipToEth = {}
        self.frdtable = []
        self.pktQueue = []
        self.fw = Firewall()
        
        #   Build a forwarding table
        f = open("forwarding_table.txt", "r")
        for line in f:
            linelst = line.split()
            linelst[0] = IPAddr(linelst[0])
            linelst[1] = IPAddr(linelst[1])
            linelst[2] = IPAddr(linelst[2])
            self.frdtable.append(linelst)
        
        #   Cache ip address to Eth address using net.interface()
        for intf in self.intf_list:
            self.frdtable.append([intf.ipaddr, intf.netmask, IPAddr("0"), intf.name])
            self.interface[intf.ipaddr] = [intf.netmask, intf.name, intf.ethaddr]
            self.devInterface[intf.name] = [intf.ethaddr, intf.ipaddr]

    def router_main(self):
        while True:
            try:
                dev,ts,pkt = self.net.recv_packet(timeout=1.0)
                self.pktQueue.append(packt(pkt))
                
                for i in self.pktQueue:
                    
                    #	ARP REQ -> ARP REPLY
                    if (i.pktElem.type == i.pktElem.ARP_TYPE):
                        if (i.pktElem.dst == pktlib.ETHER_BROADCAST):
                            self.arpReply(i.pktElem.payload)
                            self.pktQueue.remove(i)
                    
                    #	IP PKT -> ARP REQUEST
                    if (i.pktElem.type == i.pktElem.IP_TYPE):
                        print time.time()
                        if (self.fw.mainframe(i.pktElem.payload,time.time())):
                            self.addFinder(i.pktElem, i.retries)
                        self.pktQueue.remove(i)

            except SrpyNoPackets:
                # log_debug("Timeout waiting for packets")
                continue
            except SrpyShutdown:
                return
    
    def arpReply(self, e):
        '''
            This method builds and sends ARP reply in response to ARP Request.
            e = payload of original IP packet received
            '''
            #	Create ARP reply header (Ethernet)
        if (e.protodst in self.interface):
            dev = self.interface[e.protodst][1]
            ethpkt = pktlib.ethernet()
            ethpkt.src = self.interface[e.protodst][2]
            ethpkt.dst = e.hwsrc
            ethpkt.type = ethpkt.ARP_TYPE
            
            arp_rep = pktlib.arp()
            arp_rep.opcode = pktlib.arp.REPLY
            arp_rep.protosrc = e.protodst
            arp_rep.protodst = e.protosrc
            arp_rep.hwsrc = self.interface[e.protodst][2]
            arp_rep.hwdst = e.hwsrc
            
            #	Encapsulate eth packet
            ethpkt.set_payload(arp_rep)
            
            # 	Send it back to the src address
            self.net.send_packet(dev,ethpkt)
            return
    
    def addFinder(self, pkt, retries):
        ''' 
        	This method looks up destination ip addresses in the forwarding table and 
        	net.interfaces dictionary and forwards packets or calls ARP Request
        	
        	'''
        e=pkt.find('ipv4')
        longest = 0
        i = 0
        ind = -1
        
        #   Check ARP, then check frdtable
        for line in (self.frdtable):
            mask = netmask_to_cidr(line[1])
            dstIpUns = e.dstip.toUnsigned()
            pktprefix = (dstIpUns>>(32-mask))<<(32-mask)
            unsigned = str(line[0].toUnsigned())
	    	intfmask = netmask_to_cidr(line[1])
            masked = (int(unsigned)>>(32-intfmask))<<(32-intfmask)

            if (int(pktprefix) == masked):
                if (pktprefix>longest):
                    longest = pktprefix
                    nxthop = line[2]
                    ind = i
            i = i+1
            
        dev = self.frdtable[ind][3]
        drop = False
        if e.dstip in self.interface:
            drop = True
        if (ind!=-1) and not (drop):
            if dev in self.devInterface:
                seth = self.devInterface[dev][0]
                srcip = self.devInterface[dev][1]
            else:
                pass
            if e.dstip in (self.ipToEth):
                self.forwarding(dev, seth, self.ipToEth[e.dstip],pkt)
            else:
                self.arpBuilder(dev, pkt, nxthop, retries)
    
    def arpBuilder(self, dev, pkt, nexthop, retry):
        '''
            This method builds and sends ARP request
            
            '''
        if (pkt.type == pkt.IP_TYPE):
            e=pkt.payload

        if dev in self.devInterface:
            tempeth = self.devInterface[dev][0]
            tempip = self.devInterface[dev][1]
        
        ethpkt = pktlib.ethernet()
        ethpkt.src = tempeth
        ethpkt.dst = ETHER_BROADCAST
        ethpkt.type = ethpkt.ARP_TYPE
        
        #   arp header
        arp_req = pktlib.arp()
        arp_req.opcode = pktlib.arp.REQUEST
        arp_req.protosrc = tempip
        
        if (nexthop==IPAddr("0")):
            arp_req.protodst = e.dstip
        else:
            arp_req.protodst = nexthop
        
        arp_req.hwsrc = tempeth
        arp_req.hwdst = EthAddr('ff:ff:ff:ff:ff:ff')
        
        #	Encapsulate the packet and send it
        ethpkt.set_payload(arp_req)
        self.arpRequest(dev, pkt, ethpkt, retry)
        
    def arpRequest(self, dev, pkt, ethpkt, retry):
        '''
            This method sends ARP request
            
            '''
        while (retry<5):
            try:
                # 	Send a packet back to the src address
                self.net.send_packet(dev,ethpkt)
                #   Receive a packet
                dev2, ts, rplpkt = self.net.recv_packet(timeout = 1.0)
                if (rplpkt.type == rplpkt.ARP_TYPE):
                    r = rplpkt.payload
                #   Cache (IP to Eth)
                self.ipToEth[r.protosrc] = r.hwsrc
                #   Forward a packet
                self.forwarding(dev, r.hwdst, r.hwsrc, pkt)
                break
            
            except SrpyNoPackets:
                retry=retry+1
                continue
    
    def forwarding(self, dev, seth, deth, origpkt):
        
        if (origpkt.type == origpkt.IP_TYPE):
            eo = origpkt.payload
        
        eo.ttl = eo.ttl-1
        ethpkt = pktlib.ethernet()
        ethpkt.src = seth
        ethpkt.dst = deth
        ethpkt.type = ethpkt.IP_TYPE
        ethpkt.payload = origpkt.payload
        
        # 	Send a packet back to the src address
        self.net.send_packet(dev,ethpkt)

        # job's done!
        return

def srpy_main(net):
    '''
        Main entry point for router.  
        '''
    r = Router(net)
    r.router_main()
    net.shutdown()

