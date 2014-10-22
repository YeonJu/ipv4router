IPv4 Router
==========

This is a python implementation of a internet IPv4 Router with firewall
-----------------------------------------------------------------------


The primary functions of this router is

1. Respond to ARP (address resolution protocol) requests and send ARP requests
 - If the received ARP request is for a known addresses (i.e. addresses that are assigned to interfaces on the router),
 then respond with the right address
 - When Ethernet MAC address of an IP address is unknown, send ARP requests to other hosts. 

2. Receive and process packets
 - If a received packet is destined to other hosts, forward the packet to the right hosts 
 by performing address lookups in the forwarding table("longest prefix match")

This whole project is based on the POX packet and network address library.
Poxlib is a networking software platform written in Python, it provides you with

1. IP/Eth address classes
2. Ethernet/ARP/ICMP/IPv4/UDP/TCP packet classes

You can find more detailed info here: https://openflow.stanford.edu/display/ONL/POX+Wiki

