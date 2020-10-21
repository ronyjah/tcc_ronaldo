import logging
import logging.config
import logging.handlers
from configparser import ConfigParser
from threading import Thread
from subprocess import call
import sys
import argparse
from scapy.all import *
from config import Config
import time
#v_iaid = b'\x4c\x86\x70\x3c'
client_duid = b'\x00\x01\x00\x01\xc7\x92\xbc\x9a\x00\xe0\x4c\x86\x70\x3c'
server_duid = b'\x00\x01\x00\x01\x1f\xef\x03\x96\x44\x87\xfc\xba\x75\x46'
#server_duid = '000100011fef03964487fcba7546'
#c = 000100011fef03964487fcba7546
v_iaid = '4c86704c'
v_trid = '12312312'
a = client_duid
v_tgt = 'cade::cada'
src_ip = 'cade::cada'
src_mac = '00:11:22:33:44:55:66'
ip_dst ='fe80::bac0'
#DHCP6_Advertise(trid=test.get_xid())
#DHCP6OptClientId(duid=test.get_client_duid()
#DHCP6OptServerId(duid=test.get_server_duid())
#DHCP6OptIA_NA
sendp(Ether(src=src_mac)/IPv6(src='::')/ICMPv6ND_NS(tgt=v_tgt),iface='lo')
time.sleep(1)
sendp(Ether(src=src_mac)/IPv6(src=src_ip)/ICMPv6ND_NS(tgt=v_tgt),iface='lo')
time.sleep(1)
sendp(Ether(src=src_mac)/IPv6(src=src_ip)/ICMPv6ND_RS(),iface='lo')
time.sleep(1)
client_duid = b'\x00\x01\x00\x01\x1f\xef\x03\x96\x44\x87\xfc\xba\x75\x46'
sendp(Ether(src=src_mac)/IPv6(src=src_ip)/UDP()/DHCP6_Solicit(trid=int(v_trid,16))/DHCP6OptClientId(duid=a)/DHCP6OptIA_NA(iaid=int(v_iaid,16)),iface='lo')
time.sleep(1)
sendp(Ether(src=src_mac)/IPv6(src=src_ip,dst=ip_dst)/ICMPv6EchoReply(),iface='lo')
time.sleep(1)
sendp(Ether(src=src_mac)/IPv6(src=src_ip)/ICMPv6ND_RS(),iface='lo')
time.sleep(1)
#sendp(Ether(src=src_mac)/IPv6(src=src_ip)/UDP()/DHCP6_Solicit(trid=int(v_trid,16))/DHCP6OptClientId(duid=a)/DHCP6OptIA_NA(iaid=int(v_iaid,16)),iface='lo')
#time.sleep(2)
sendp(Ether(src=src_mac)/IPv6(src=src_ip)/UDP()/DHCP6_Request(),iface='lo')
#time.sleep(1)
#sendp(Ether(src=src_mac)/IPv6(src=src_ip)/UDP()/DHCP6_Request(),iface='lo')
#time.sleep(2)
#sendp(Ether(src=src_mac,dst='00:00:00:00:a0:a0')/IPv6(src=src_ip,dst=ip_dst)/ICMPv6EchoReply(),count=3,inter=1,iface='lo')
#time.sleep(2)
sendp(Ether(src=src_mac)/IPv6(src=src_ip)/UDP()/DHCP6(msgtype=5)/DHCP6_Renew(),count=3,inter=1, iface='lo')