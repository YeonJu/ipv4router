import time
import sys
import os
import os.path
sys.path.append(os.path.join(os.environ['HOME'],'pox'))
sys.path.append(os.path.join(os.getcwd(),'pox'))
import pox.lib.packet as pktlib
from pox.lib.packet import ethernet,ETHER_BROADCAST,IP_ANY
from pox.lib.packet import arp,ipv4,icmp,unreach,udp,tcp
from pox.lib.addresses import EthAddr,IPAddr,netmask_to_cidr,cidr_to_netmask,parse_cidr


class Firewall(object):
    def __init__(self):
        self.protocol={'ip':'*', 'udp':17, 'tcp':6, 'icmp':1}
        self.rules = []
        self.firewall=[]
        self.time=time.time()
        self.token=[]
        
        # import rules from firewall_rules.txt
        f = open("firewall_rules.txt","r")
        self.rules = [l for l in (line.strip() for line in f) if l and l[0]!="#"]

    def mainframe(self, pkt, t):
        self.time = t
        self.firewallInit()
        return self.allow(pkt)

    def firewallInit(self):
        ind = 0
        for rule in self.rules:
            field = rule.split()
            temp={}
            action, type = field[0:2]
            rtlimit = 65535
            src = self.toInt(IPAddr(0),0)
            dst = self.toInt(IPAddr(0),0)
            srcpt, dstpt, srcip, dstip = ['*', '*', '*', '*']
            srccidr, dstcidr = [0, 0]

            if (field[0]=='deny'):
                action = False
            type = protocol[field[1]]
       
            for i in range(2, len(field)):
                if (field[i] == 'src') and (field[i+1]!='any'):
                    srcip, srccidr = parse_cidr(field[i+1])
                    src=self.toInt(srcip, srccidr)
                elif (field[i] == 'dst') and (field[i+1]!='any'):
                    dstip, dstcidr = parse_cidr(field[i+1])
                    dst=self.toInt(dstip, dstcidr)
                elif (field[i] == 'srcport') and (field[i+1]!='any'):
                    srcpt=int(field[i+1])
                elif (field[i] == 'dstport') and (field[i+1]!='any'):
                    dstpt=int(field[i+1])
                elif (field[i] == 'ratelimit'):
                    rtlimit=int(field[i+1])
    
            self.append([action,type,srcip,srccidr,dstip,dstcidr,srcpt,dstpt,rtlimit,ind])
            self.firewall.append([type,src,dst,srcpt,dstpt])
            self.token.append(0)
            ind+=1

    def toInt(self, ip, cidr):
        ''' 
            Generates unsigned ip address/ip address prefix.
            '''
        ipUns = ip.toUnsigned()
        masked = (ipUns>>(32-cidr))<<(32-cidr)
        return masked

    def cmp(self, a, b):
        ''' 
            Compares list a and list b and returns boolean value
            '''
        return all(c0 == c1 or (c0 == '*') for c0, c1 in zip(a, b))

    def allow(self, pkt):
        '''
            Checks if the received packet matches any firewall rules. 
            If it matches, then the packet will be sent to the filter method, 
            otherwise packet is allowed to reach the router.
            '''
        try:
            type = pkt.protocol
            srcip = pkt.srcip
            dstip = pkt.dstip
            srcpt, dstpt = ['*','*']
            pktInfo = []

            if (type == 17 or type == 6):
                srcpt = pkt.payload.srcport
                dstpt = pkt.payload.dstport

            for i in range(0, len(self.)):
                srcUns = self.toInt(srcip,self.[i][3])
                dstUns = self.toInt(dstip,self.[i][5])
                pktInfo=[pkt.protocol,srcUns,dstUns,srcpt,dstpt]
                match = self.cmp(self.firewall[i],pktInfo)

                if (match):
                    rule = self.[i]
                    return self.filter(pkt, rule)
            return True

        except AttributeError:
            return False

    def filter(self, pkt, rule):
        '''
            Returns True if the packet passes all the firewall rules, 
            and False otherwise
            '''
        ind = int(rule[9])
        self.setToken(ind, int(rule[8]), self.time)
        tries = 0
        while (rule[0]=='permit') and (tries<4):
            if (len(pkt)<=self.token[ind]):
                self.token[ind]-=len(pkt)
                return True
            self.updateToken(ind, int(rule[8]))
            tries+=1
        return False
    
    def setToken(self, ind, r, t):
        '''
            Calculates time differences between the point of router receiving 
            the packet and the current time, and add cumulative value to the token according 
            to that time difference
            '''
        cur = time.time()
        timepassed = (cur-t)*2
        while (timepassed>0):
            self.token[ind]+=r/2
            timepassed-=1
        if self.token[ind]>(r*2):
            self.token[ind] = r*2
        return

    def updateToken(self, ind, r):
        '''
            Updates token value as time passes
            '''
        while (self.token[ind]<(2*r)):
            time.sleep(0.5)
            self.token[ind]+=r/2
        if (self.token[ind]>(r*2)):
            self.token[ind] = r*2
        return

def tests():
    f = Firewall()
    ip = ipv4()
    ip.srcip = IPAddr("172.16.42.1")
    ip.dstip = IPAddr("172.16.42.35")
    # 17 for udp, 6 tcp, 1 icmp
    ip.protocol = 6

    icmppkt = pktlib.icmp()
    icmppkt.type = pktlib.TYPE_ECHO_REQUEST
    icmppkt.payload ="Hello, world"
    
    xudp = udp()
    xudp.srcport = 53
    xudp.dstport = 53
    xudp.payload = "Hello, world"
    xudp.len = 8 + len(xudp.payload)
    
    tcppkt = pktlib.tcp()
    tcppkt.SYN = 1
    tcppkt.seq = 14
    tcppkt.srcport = 80
    tcppkt.dstport = 80
    tcppkt.offset = 5
    tcppkt.payload = "Hello, world"
    tcppkt.tcplen = 20
    
#    ip.payload = xudp
#    ip.payload = icmppkt
    ip.payload = tcppkt

    f=Firewall()
    f.mainframe(ip, time.time())

if __name__ == '__main__':
    # only call tests() if this file gets invoked directly,
    # not if it is imported.

    tests()
