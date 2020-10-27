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
from packetsniffer import PacketSniffer
from commontestsetup1_1 import CommonTestSetup1_1
from sendmsgs import SendMsgs
from configsetup1_1 import ConfigSetup1_1
import pdb
format = "%(asctime)s: %(message)s"
logging.basicConfig(format=format, level=logging.DEBUG,
                    datefmt="%H:%M:%S")

class Test166b:

    def __init__(self,config,app):
        self.__queue_wan = Queue()
        self.__queue_lan = Queue()
        self.__config = config
        self.__interface = None
        self.__pkt = None
        self.addr_ceRouter = None
        self.mac_ceRouter = None
        self.__local_addr_ceRouter =None
        self.__ND_local_OK = False
        self.__sendmsgs = SendMsgs(self.__config)
        self.__config_setup1_1 = ConfigSetup1_1(self.__config)
        self.__wan_device_tr1 = self.__config.get('wan','device_wan_tr1')
        self.__wan_mac_tr1 = self.__config.get('wan','wan_mac_tr1')
        self.__link_local_addr = self.__config.get('wan','link_local_addr')
        self.__all_nodes_addr = self.__config.get('multicast','all_nodes_addr')
        self.__test_desc = self.__config.get('tests','1.6.6b')
        

    def get_addr_ceRouter(self):
        return self.addr_ceRouter
    
    def get_mac_ceRouter(self):
        return self.mac_ceRouter

    def set_flags(self):
        self.__config_setup1_1.set_flag_M(self.__config.get('t1.6.6b','flag_m'))
        self.__config_setup1_1.set_flag_0(self.__config.get('t1.6.6b','flag_o'))
        self.__config_setup1_1.set_flag_chlim(self.__config.get('t1.6.6b','flag_chlim'))
        self.__config_setup1_1.set_flag_L(self.__config.get('t1.6.6b','flag_l'))
        self.__config_setup1_1.set_flag_A(self.__config.get('t1.6.6b','flag_a'))
        self.__config_setup1_1.set_flag_R(self.__config.get('t1.6.6b','flag_r'))
        self.__config_setup1_1.set_flag_prf(self.__config.get('t1.6.6b','flag_prf'))
        self.__config_setup1_1.set_validlifetime(self.__config.get('t1.6.6b','validlifetime'))
        self.__config_setup1_1.set_preferredlifetime(self.__config.get('t1.6.6b','preferredlifetime'))
        self.__config_setup1_1.set_routerlifetime(self.__config.get('t1.6.6b','routerlifetime'))
        self.__config_setup1_1.set_intervalo(self.__config.get('t1.6.6b','intervalo'))    

    def run(self):
        self.__packet_sniffer_wan = PacketSniffer('test166b',self.__queue_wan,self,self.__config,self.__wan_device_tr1)
        self.__packet_sniffer_wan.start()

        self.set_flags()         
        logging.info(self.__test_desc)
        t_test = 0
        sent_reconfigure = False
        time_over = False
        rs_ok = False
        send_ra = False
        send_ns =False
        send_ra2 = False
        while not self.__queue_wan.full():
            while self.__queue_wan.empty():
                if t_test < 60:
                    time.sleep(1)
                    t_test = t_test + 1
                else:
                    time_over = True
            pkt = self.__queue_wan.get()
            #if not self.__ND_local_OK:

            if pkt.haslayer(ICMPv6ND_NS):

                if pkt[ICMPv6ND_NS].tgt == '::':

                    pass
                if pkt[IPv6].src == self.__config.get('wan','link_local_addr'):
                    pass
                if pkt[IPv6].src == self.__config.get('wan','global_wan_addr'):
                    pass
                if pkt[IPv6].src == '::':
                    if pkt[ICMPv6ND_NS].tgt != '::':

                        self.__config_setup1_1.set_mac_ceRouter(pkt[Ether].src)

                        self.__config_setup1_1.set_local_addr_ceRouter(pkt[ICMPv6ND_NS].tgt)

                        self.__ND_local_OK = True

                    if pkt[ICMPv6ND_NS].tgt != '::' and pkt[IPv6].src != '::':

                        pkt.show()


            if pkt.haslayer(ICMPv6ND_RS) and not self.__ND_local_OK:
                return False
            else:
                if not send_ns:
                    #self.__sendmsgs.set_flags_common_setup(self.__config_setup1_1)
                    self.__config_setup1_1.set_ether_src(self.__config.get('wan','link_local_mac'))
                    self.__config_setup1_1.set_ether_dst(self.__config.get('multicast','all_mac_nodes'))
                    self.__config_setup1_1.set_ipv6_src(self.__config.get('wan','global_wan_addr'))
                    self.__config_setup1_1.set_ipv6_dst(self.__config.get('multicast','all_nodes_addr'))
                    self.__config_setup1_1.set_tgt(self.__config.get('wan','link_local_addr'))
                    
                    self.__sendmsgs.send_icmp_ns(self.__config_setup1_1)
                    send_ns = True
                    continue
                if send_ns and not send_ra:       
                    self.__config_setup1_1.set_flag_M("0")
                    self.__config_setup1_1.set_flag_0("0")
                    self.__config_setup1_1.set_ether_src(self.__config.get('wan','ra_mac'))
                    self.__config_setup1_1.set_ether_dst(self.__config.get('multicast','all_mac_nodes'))
                    self.__config_setup1_1.set_ipv6_src(self.__config.get('wan','link_local_addr'))
                    self.__config_setup1_1.set_ipv6_dst(self.__config.get('multicast','all_nodes_addr'))
                    self.__sendmsgs.send_tr1_RA(self.__config_setup1_1)
                    send_ra = True
                    continue
                    #self.set_ether_dst(pkt[Ether].src)

                if send_ra:
                    if pkt.haslayer(DHCP6_Solicit):
                        if pkt.haslayer(DHCP6OptIA_NA):
                            return True
                        else:
                            return False 

    
        self.__packet_sniffer_wan.stop()
        return False
     
        