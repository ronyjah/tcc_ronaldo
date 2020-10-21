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

# - Seleciona a interface
# - recebe thread de captura das mensagens já iniciada na main
# - inicia a captura
# - recebe o pacote e armazena numa lista
# - analisa o pacote recebido e armazenado na lista
# - 

format = "%(asctime)s: %(message)s"
logging.basicConfig(format=format, level=logging.DEBUG,
                    datefmt="%H:%M:%S")


class Test162a:

    def __init__(self,config):
        self.__queue_wan = Queue()
        self.__queue_lan = Queue()
        logging.info('self.__queue_size_inicio162')
        logging.info(self.__queue_wan.qsize())
        self.__config = config
        self.__interface = None
        self.__pkt = None
        self.__valid = False
        self.__result = None
        self.__device_lan_tn1 = None
        self.__lan_mac_tn1 = None
        self.__ceRouter_mac_addr = None
        self.__flag_M = None
        self.__flag_O = None
        self.__flag_chlim = None
        self.__flag_L = None
        self.__flag_A = None
        self.__flag_R = None
        self.__validlifetime = None
        self.__preferredlifetime = None
        self.__interval = None
        self.__routerlifetime = None
        self.__ipv6_dst =None
        self.__ipv6_src = None
        self.__ether_src = None
        self.__ether_dst = None
        self.__xid = None
        self.__duid = None
        self.__ND_local_OK = False
        self.__setup1_1_OK = False
        self.__local_ping_OK = False
        self.__global_ns_ok = False
        self.__dhcp_ok = False
        self.__local_addr_ceRouter =None
        self.__CommonSetup1_1 = CommonTestSetup1_1(self.__config)
        self.__wan_device_tr1 = self.__config.get('wan','device_wan_tr1')
        self.__wan_mac_tr1 = self.__config.get('wan','wan_mac_tr1')
        self.__link_local_addr = self.__config.get('wan','link_local_addr')
        self.__all_nodes_addr = self.__config.get('multicast','all_nodes_addr')
        self.__test_desc = self.__config.get('tests','1.6.2')
        
        #self.__packet_sniffer.daemon=True
        

    #recebe o pacote
    #packetSniffer return pkt


    def set_result(self, valor):
        self.__result = valor
        
    def get_result(self):
        return self.__result

    def send_icmpv6_ra(self,pkt):
        et = Ether(src=self.__wan_mac_tr1)#,\
                   #dst=pkt[Ether].src)
        ip = IPv6(src=self.__link_local_addr,\
                  dst=self.__all_nodes_addr)
        icmp_ra = ICMPv6ND_RA()
        sendp(et/ip/icmp_ra,iface=self.__wan_device_tr1)

    def send_echo_request_lan(self):
        et = Ether(src=self.__wan_mac_tr1,\
                   dst=self.__ceRouter_mac_addr)
        ip = IPv6(src=self.__link_local_addr,\
                  dst=self.__all_nodes_addr)
        icmp_ra = ICMPv6EchoRequest()
        sendp(et/ip/icmp_ra,iface=self.__wan_device_tr1)

    def flags_partA(self):
        self.__flag_M = self.__config.get('t1.6.2_flags_part_a','flag_m')
        self.__flag_O = self.__config.get('t1.6.2_flags_part_a','flag_o')
        self.__flag_chlim = self.__config.get('t1.6.2_flags_part_a','flag_chlim')
        self.__flag_L = self.__config.get('t1.6.2_flags_part_a','flag_l')
        self.__flag_A = self.__config.get('t1.6.2_flags_part_a','flag_a')
        self.__flag_R = self.__config.get('t1.6.2_flags_part_a','flag_r')
        self.__validlifetime = self.__config.get('t1.6.2_flags_part_a','validlifetime')
        self.__preferredlifetime = self.__config.get('t1.6.2_flags_part_a','preferredlifetime')
        self.__routerlifetime = self.__config.get('t1.6.2_flags_part_a','routerlifetime')
        self.__intervalo = self.__config.get('t1.6.2_flags_part_a','intervalo')

    def flags_partB(self):
        self.__flag_M = self.__config.get('t1.6.2_flags_part_b','flag_m')
        self.__flag_O = self.__config.get('t1.6.2_flags_part_b','flag_o')
        self.__flag_chlim = self.__config.get('t1.6.2_flags_part_b','flag_chlim')
        self.__flag_L = self.__config.get('t1.6.2_flags_part_b','flag_l')
        self.__flag_A = self.__config.get('t1.6.2_flags_part_b','flag_a')
        self.__flag_R = self.__config.get('t1.6.2_flags_part_b','flag_r')
        self.__validlifetime = self.__config.get('t1.6.2_flags_part_b','validlifetime')
        self.__preferredlifetime = self.__config.get('t1.6.2_flags_part_b','preferredlifetime')
        self.__routerlifetime = self.__config.get('t1.6.2_flags_part_b','routerlifetime')
        self.__intervalo = self.__config.get('t1.6.2_flags_part_b','intervalo')


    def get_flag_M(self):
        return int(self.__flag_M)
        
    def get_flag_O(self):
        return int(self.__flag_O)

    def get_flag_chlim(self):
        return int(self.__flag_chlim)

    def get_flag_L(self):
        return  int(self.__flag_L)

    def get_flag_A(self):
        return int(self.__flag_A)

    def get_flag_R(self):
        return int(self.__flag_R)

    def get_validlifetime(self):
        return int(self.__validlifetime)

    def get_preferredlifetime(self):
        return int(self.__preferredlifetime)

    def get_interval(self):
        return int(self.__intervalo)

    def get_routerlifetime(self):
        return int(self.__routerlifetime)
    
    def set_ipv6_dst(self, valor):
        self.__ipv6_dst = valor

    def get_ipv6_dst(self):
        return self.__ipv6_dst

    def set_ipv6_src(self, valor):
        self.__ipv6_src = valor

    def get_ipv6_src(self):
        return self.__ipv6_src

    def set_ether_dst(self, valor):
        self.__ether_dst = valor

    def get_ether_dst(self):
        return self.__ether_dst

    def set_ether_src(self, valor):
        self.__ether_src = valor

    def get_ether_src(self):
        return self.__ether_src
    
    def set_local_addr_ceRouter(self,valor):
        self.__local_addr_ceRouter = valor

    def get_local_addr_ceRouter(self):
        return self.__local_addr_ceRouter

    def set_tgt(self,valor):
        self.__tgt = valor

    def get_tgt(self):
        return self.__tgt

    def set_xid(self,valor):
        self.__xid = valor

    def get_xid(self):
        return self.__xid

    def set_duid(self,valor):
        self.__duid = valor

    def get_duid(self):
        return self.__duid

    def setup1_1(self,pkt):
        
        if pkt.haslayer(ICMPv6ND_RS):
            logging.info('RS')
            self.set_ether_src(self.__config.get('wan','ra_address'))
            self.set_ether_dst(self.__config.get('multicast','all_mac_nodes'))
            self.set_ipv6_src(self.__config.get('wan','ra_address'))
            self.set_ipv6_dst(self.__config.get('multicast','all_nodes_addr'))

            self.__CommonSetup1_1.send_tr1_RA(self)
        
        if pkt.haslayer(ICMPv6ND_NS):
            
            if pkt[ICMPv6ND_NS].tgt:
                self.set_ether_dst(pkt[Ether].src)
                self.set_local_addr_ceRouter(pkt[ICMPv6ND_NS].tgt)
                self.__ND_local_OK = True

        if pkt.haslayer(DHCP6_Solicit):
            self.set_xid(pkt[DHCP6_Solicit].trid)
            self.set_duid(pkt[DHCP6OptClientId].duid)
            self.set_ether_src(self.__config.get('wan','link_local_mac'))
            self.set_ether_dst(self.get_ether_dst())
            self.set_ipv6_dst(self.get_local_addr_ceRouter())
            self.set_ipv6_src(self.__config.get('wan','link_local_addr'))
            self.__CommonSetup1_1.send_dhcp_advertise(self)

        if pkt.haslayer(DHCP6_Request):
            self.set_ether_src(self.__config.get('wan','link_local_mac'))
            self.set_ether_dst(self.get_ether_dst())
            self.set_ipv6_dst(self.get_local_addr_ceRouter())
            self.set_ipv6_src(self.__config.get('wan','link_local_addr'))
            self.__CommonSetup1_1.send_dhcp_reply(self)
            self.__dhcp_ok = True
            self.__setup1_1_OK = True

        if self.__dhcp_ok:
            self.set_ether_src(self.__config.get('multicast','all_mac_nodes'))
            self.set_ether_dst(self.__config.get('wan','link_local_mac'))
            self.set_ipv6_dst(self.__config.get('multicast','all_nodes_addr'))
            self.set_ipv6_src(self.__config.get('wan','global_wan_addr'))
            self.set_tgt(self.__config.get('wan','link_local_addr'))
            self.__CommonSetup1_1.send_icmp_ns(self)
            self.__global_ns_ok = True

          

        #1 sned ping test
        if self.__ND_local_OK and not self.__local_ping_OK:
            self.set_ipv6_src(self.__config.get('wan','link_local_addr'))
            self.set_ipv6_dst(self.get_local_addr_ceRouter())
            self.set_ether_src(self.__config.get('wan','link_local_mac'))
            self.set_ether_dst(self.get_ether_dst())
            self.__CommonSetup1_1.send_echo_request(self)
            self.__local_ping_OK = True


        if pkt.haslayer(ICMPv6EchoReply):
            print('DESTINO IPv6:' + pkt[IPv6].dst)
            if pkt[IPv6].dst == self.__config.get('wan','link_local_addr'):
                self.__local_ping_OK = True

    def run(self):
        self.__packet_sniffer_wan = PacketSniffer('test162',self.__queue_wan,self,self.__config,self.__wan_device_tr1)
        #self.__packet_sniffer.init()
        self.flags_partA()
        self.__CommonSetup1_1.set_flags_common_setup(self)
        #self.__CommonSetup1_1.send_tr1_RA()
        #self.__CommonSetup1_1.send_dhcp_advertise()
        #self.__CommonSetup1_1.send_dhcp_reply()
        #self.__CommonSetup1_1.send_echo_request()
        #self.set_ipv6_dst('ff:ff::1')
        #self.__config.set('setup1-1_advertise','ipv6_addr','ff:ff::1')
        #self.__CommonSetup1_1.ipv6()
        #self.__CommonSetup1_1.send_tr1_RA(self)
        #time.sleep(100000000)
        

        self.__packet_sniffer_wan.start()
        logging.info('Task Desc')
        logging.info(self.__test_desc)
        logging.info('Qsize')
        logging.info(self.__queue_wan.qsize())
        while not self.__queue_wan.full():

            pkt = self.__queue_wan.get()
            if not self.__setup1_1_OK:
                logging.info('self.__queue_size')
                logging.info(self.__queue_wan.qsize())
                self.setup1_1(pkt)

            elif not self.__approved:
                self.set_ipv6_src(self.__config.get('wan','global_wan_addr'))
                self.set_ipv6_dst(self.__config.get('setup1-1_advertise','ia_na_address'))
                self.set_ether_src(self.__config.get('wan','link_local_mac'))
                self.set_ether_dst(self.get_ether_dst())
                self.__CommonSetup1_1.send_echo_request(self)
                if pkt.haslayer(ICMPv6EchoReply):
                    mac_dst = pkt[Ether].dst
                    if mac_dst == self.__config.get('wan','link_local_mac'):
                        return True
                    else:
                        return False
            #time.sleep(10000000)
            # if pkt.haslayer(ICMPv6ND_RA):
            #     self.set_ipv6_dst(pkt[IPv6].src)
            #     self.set_ether_dst(pkt[Ether].src)
                #self.__CommonSetup1_1.ipv6(self)
                #self.__ceRouter_mac_addr=pkt[Ether].src
                #self.__CommonSetup1_1.send_tr1_RA(self)
                # self.__CommonSetup1_1.send_echo_request(self)
                #self.send_icmpv6_ra(pkt)
            #time.sleep(1)
                #break
                #self.__valid = True
            #elif pkt.haslayer(ICMPv6ND_RA) and self.__valid == False:
                #print('theardoffFalse')
                #self.turn_off_thread()
             #   return False
            #else:
                
                #print('theardofftrue')
                #self.turn_off_thread()
             #   return True
        while not self.__queue_wan.empty():
            print('RS1')
            pkt = self.__queue_wan.get()       
        logging.info('Passo4-t162run_sttop-theard success')
        logging.info('self.__queue_size_fim')
        logging.info(self.__queue_wan.qsize())  
            #time.sleep(2)
        self.__packet_sniffer_wan.stop()
            #time.sleep(2)
        return True
     
        